import os
import hmac
import secrets
from datetime import date
from decimal import Decimal, InvalidOperation

import bcrypt
import psycopg2

from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from database import get_db_connection

from flask import request, jsonify, session
from psycopg2.extras import RealDictCursor

# konfigurasi aplikasi
load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError("FLASK_SECRET_KEY belum diatur di .env")


# verifikasi password akun
def verify_password(input_password, stored_password):

    if not isinstance(stored_password, str):
        return False

    # password dengan hash werkzeug
    if stored_password.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(stored_password, input_password)

    # password dengan hash bcrypt
    if stored_password.startswith(("$2a$", "$2b$", "$2y$")):
        try:
            return bcrypt.checkpw(
                input_password.encode("utf-8"),
                stored_password.encode("utf-8")
            )
        except ValueError:
            return False

    # dukungan password plaintext dari data pengujian lama
    return hmac.compare_digest(input_password, stored_password)



# ringkasan budget sesuai biro, tahun, dan entity
def get_pengusul_budget_summary(user_id, budget_year, entity_id=None):

    conn = get_db_connection()

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    COALESCE(SUM(bm.consumable_budget), 0),
                    COALESCE(SUM(bm.consumed_budget), 0),
                    COALESCE(SUM(bm.available_amount), 0)

                FROM public.budget_master AS bm

                JOIN public.biro AS b
                    ON bm.biro_id = b.biro_id
                   AND bm.entity_id = b.entity_id

                WHERE b.biro_code = (
                    SELECT b_user.biro_code

                    FROM public.users AS u

                    JOIN public.biro AS b_user
                        ON u.biro_id = b_user.biro_id
                       AND u.entity_id = b_user.entity_id

                    WHERE u.user_id = %s
                      AND u.role = 'Pengusul'
                )

                AND bm.budget_year = %s

                AND (%s::integer IS NULL OR bm.entity_id = %s)
                """,
                (
                    user_id,
                    budget_year,
                    entity_id,
                    entity_id
                )
            )

            consumable, consumed, available = cursor.fetchone()

        return {
            "consumable_budget": consumable,
            "consumed_budget": consumed,
            "available_amount": available
        }

    finally:
        conn.close()


# mengambil periode tahun berdasarkan kode biro lintas entity
def get_budget_years(user_id):

    conn = get_db_connection()

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT DISTINCT bm.budget_year

                FROM public.budget_master AS bm

                JOIN public.biro AS b
                    ON bm.biro_id = b.biro_id
                   AND bm.entity_id = b.entity_id

                WHERE b.biro_code = (
                    SELECT b_user.biro_code

                    FROM public.users AS u

                    JOIN public.biro AS b_user
                        ON u.biro_id = b_user.biro_id
                       AND u.entity_id = b_user.entity_id

                    WHERE u.user_id = %s
                      AND u.role = 'Pengusul'
                )

                AND bm.budget_year IS NOT NULL

                ORDER BY bm.budget_year DESC
                """,
                (user_id,)
            )

            return [row[0] for row in cursor.fetchall()]

    finally:
        conn.close()


# grafik penggunaan per commitment item
def get_pengusul_commitment_chart(user_id, budget_year, entity_id=None):

    conn = get_db_connection()

    try:
        with conn.cursor() as cursor:

            # cari kolom nama commitment item yang tersedia
            cursor.execute(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'commitment_item'
                """
            )

            available_columns = {
                row[0]
                for row in cursor.fetchall()
            }

            # pilih nama kolom yang tersedia dalam database
            if "commitment_item_name" in available_columns:
                name_expression = "ci.commitment_item_name"

            elif "ci_name" in available_columns:
                name_expression = "ci.ci_name"

            elif "description" in available_columns:
                name_expression = "ci.description"

            elif "commitment_item_description" in available_columns:
                name_expression = "ci.commitment_item_description"

            else:
                name_expression = "''"

            query = f"""
                SELECT
                    ci.commitment_item_code,
                    {name_expression} AS commitment_item_name,
                    COALESCE(
                        SUM(bm.consumed_budget),
                        0
                    ) AS total_consumed

                FROM public.budget_master AS bm

                JOIN public.biro AS b
                    ON bm.biro_id = b.biro_id
                   AND bm.entity_id = b.entity_id

                JOIN public.commitment_item AS ci
                    ON bm.commitment_item_id = ci.commitment_item_id

                WHERE b.biro_code = (
                    SELECT b_user.biro_code

                    FROM public.users AS u

                    JOIN public.biro AS b_user
                        ON u.biro_id = b_user.biro_id
                       AND u.entity_id = b_user.entity_id

                    WHERE u.user_id = %s
                      AND u.role = 'Pengusul'
                )

                AND bm.budget_year = %s

                AND (
                    %s::integer IS NULL
                    OR bm.entity_id = %s
                )

                GROUP BY
                ci.commitment_item_id,
                    ci.commitment_item_code

                ORDER BY total_consumed DESC
                LIMIT 10
            """

            cursor.execute(
                query,
                (
                    user_id,
                    budget_year,
                    entity_id,
                    entity_id
                )
            )

            rows = cursor.fetchall()

        return [
            {
                "label": str(code),
                "name": str(name or ""),
                "amount": float(amount)
            }
            for code, name, amount in rows
        ]

    finally:
        conn.close()


# halaman login
@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        flash("Username dan password wajib diisi.", "danger")
        return redirect(url_for("login"))

    conn = None

    try:
        conn = get_db_connection()

        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    user_id,
                    username,
                    password,
                    role,
                    entity_id,
                    biro_id

                FROM public.users

                WHERE LOWER(username) = LOWER(%s)
                LIMIT 1
                """,
                (username,)
            )

            user = cursor.fetchone()

        if not user or not verify_password(password, user[2]):
            flash("Username atau password tidak sesuai.", "danger")
            return redirect(url_for("login"))

        user_id, db_username, _, role, entity_id, biro_id = user

        if role not in ("Pengusul", "Approval"):
            flash("Role pengguna tidak dikenali.", "danger")
            return redirect(url_for("login"))

        if role == "Pengusul":

            if entity_id is None or biro_id is None:
                flash("Identitas Biro belum tersedia.", "danger")
                return redirect(url_for("login"))

            # validasi relasi biro akun sebelum masuk ke website
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT 1
                    FROM public.biro
                    WHERE biro_id = %s
                      AND entity_id = %s
                    """,
                    (biro_id, entity_id)
                )

                if cursor.fetchone() is None:
                    flash("Identitas Biro tidak ditemukan.", "danger")
                    return redirect(url_for("login"))

        # simpan session pengguna
        session.clear()

        session.update({
            "user_id": user_id,
            "username": db_username,
            "role": role,
            "entity_id": entity_id,
            "biro_id": biro_id
        })

    except psycopg2.Error:
        app.logger.exception("Gagal melakukan login")
        flash("Login gagal diproses.", "danger")
        return redirect(url_for("login"))

    finally:
        if conn is not None:
            conn.close()

    # pengusul masuk ke profil, approval masuk ke dashboard
    if role == "Pengusul":
        return redirect(url_for("profil"))

    return redirect(url_for("dashboard"))


# registrasi akun approval
@app.route("/register-approval", methods=["GET", "POST"])
def register_approval():

    if request.method == "GET":
        return render_template("register_approval.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")
    approval_code = request.form.get("approval_code", "")

    if not username or len(username) > 255:
        flash("Username wajib diisi dan maksimal 255 karakter.", "danger")
        return redirect(url_for("register_approval"))

    if len(password) < 8:
        flash("Password minimal 8 karakter.", "danger")
        return redirect(url_for("register_approval"))

    if password != confirm_password:
        flash("Konfirmasi password tidak sesuai.", "danger")
        return redirect(url_for("register_approval"))

    # validasi kode registrasi approval
    valid_code = os.getenv("APPROVAL_CODE")

    if not valid_code:
        raise RuntimeError("APPROVAL_CODE belum diatur di .env")

    if not hmac.compare_digest(approval_code, valid_code):
        flash("Kode Approval tidak sesuai.", "danger")
        return redirect(url_for("register_approval"))

    conn = None

    try:
        conn = get_db_connection()

        with conn:
            with conn.cursor() as cursor:

                # cek username yang sudah terdaftar
                cursor.execute(
                    """
                    SELECT 1

                    FROM public.users

                    WHERE LOWER(username) = LOWER(%s)
                    LIMIT 1
                    """,
                    (username,)
                )

                if cursor.fetchone():
                    flash("Username sudah digunakan.", "danger")
                    return redirect(url_for("register_approval"))

                # simpan akun approval baru
                cursor.execute(
                    """
                    INSERT INTO public.users (
                        username,
                        password,
                        role,
                        entity_id,
                        biro_id
                    )

                    VALUES (%s, %s, 'Approval', NULL, NULL)
                    """,
                    (
                        username,
                        generate_password_hash(password)
                    )
                )

        flash("Registrasi berhasil! Silakan login.", "success")
        return redirect(url_for("login"))

    except psycopg2.errors.UniqueViolation:
        flash("Username sudah digunakan.", "danger")
        return redirect(url_for("register_approval"))

    except psycopg2.Error:
        app.logger.exception("Registrasi approval gagal")
        flash("Registrasi gagal diproses.", "danger")
        return redirect(url_for("register_approval"))

    finally:
        if conn is not None:
            conn.close()


# halaman profil pengusul
@app.route("/profil")
def profil():

    if not session.get("user_id"):
        flash("Silakan login terlebih dahulu.", "danger")
        return redirect(url_for("login"))

    if session.get("role") != "Pengusul":
        return redirect(url_for("dashboard"))

    conn = None

    try:
        conn = get_db_connection()

        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    u.username,
                    u.role,
                    b.biro_code,
                    b.biro_name

                FROM public.users AS u

                JOIN public.biro AS b
                    ON u.biro_id = b.biro_id
                   AND u.entity_id = b.entity_id

                WHERE u.user_id = %s
                  AND u.role = 'Pengusul'
                """,
                (session["user_id"],)
            )

            result = cursor.fetchone()

        if result is None:
            session.clear()
            flash("Akun Pengusul tidak ditemukan.", "danger")
            return redirect(url_for("login"))

        user = {
            "username": result[0],
            "role": result[1],
            "biro_code": result[2],
            "biro_name": result[3]
        }

        return render_template(
            "profil_pengusul.html",
            user=user
        )

    except psycopg2.Error:
        app.logger.exception("Gagal mengambil profil pengusul")
        flash("Data profil gagal dimuat.", "danger")
        return redirect(url_for("dashboard"))

    finally:
        if conn is not None:
            conn.close()


# ubah password pengusul
@app.route("/ubah-password", methods=["POST"])
def ubah_password():

    if not session.get("user_id"):
        flash("Silakan login terlebih dahulu.", "danger")
        return redirect(url_for("login"))

    if session.get("role") != "Pengusul":
        return redirect(url_for("dashboard"))

    password_lama = request.form.get("password_lama", "")
    password_baru = request.form.get("password_baru", "")
    konfirmasi = request.form.get("konfirmasi_password", "")

    if not password_lama or not password_baru or not konfirmasi:
        flash("Semua kolom password wajib diisi.", "danger")
        return redirect(url_for("profil"))

    if len(password_baru) < 8:
        flash("Password baru minimal 8 karakter.", "danger")
        return redirect(url_for("profil"))

    if password_baru != konfirmasi:
        flash("Konfirmasi password baru tidak sesuai.", "danger")
        return redirect(url_for("profil"))

    if password_baru == password_lama:
        flash("Password baru harus berbeda dari password lama.", "danger")
        return redirect(url_for("profil"))

    conn = None

    try:
        conn = get_db_connection()

        with conn:
            with conn.cursor() as cursor:

                cursor.execute(
                    """
                    SELECT password

                    FROM public.users

                    WHERE user_id = %s
                      AND role = 'Pengusul'

                    FOR UPDATE
                    """,
                    (session["user_id"],)
                )

                result = cursor.fetchone()

                if not result or not verify_password(
                    password_lama,
                    result[0]
                ):
                    flash("Password lama tidak sesuai.", "danger")
                    return redirect(url_for("profil"))

                # simpan password baru
                cursor.execute(
                    """
                    UPDATE public.users
                    SET password = %s
                    WHERE user_id = %s
                      AND role = 'Pengusul'
                    """,
                    (
                        generate_password_hash(password_baru),
                        session["user_id"]
                    )
                )

        flash("Password berhasil diperbarui.", "success")
        return redirect(url_for("profil"))

    except psycopg2.Error:
        app.logger.exception("Gagal mengubah password")
        flash("Password gagal diperbarui.", "danger")
        return redirect(url_for("profil"))

    finally:
        if conn is not None:
            conn.close()



# mengambil daftar entity yang dimiliki biro pengusul
def get_pengusul_entity_options(user_id):

    conn = get_db_connection()

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT DISTINCT
                    ue.entity_id,
                    ue.unit_entity

                FROM public.biro AS b

                JOIN public.unit_entity AS ue
                    ON b.entity_id = ue.entity_id

                WHERE b.biro_code = (
                    SELECT b_user.biro_code

                    FROM public.users AS u

                    JOIN public.biro AS b_user
                        ON u.biro_id = b_user.biro_id
                       AND u.entity_id = b_user.entity_id

                    WHERE u.user_id = %s
                      AND u.role = 'Pengusul'
                )

                ORDER BY ue.unit_entity
                """,
                (user_id,)
            )

            rows = cursor.fetchall()

        return [
            {
                "entity_id": row[0],
                "unit_entity": row[1]
            }
            for row in rows
        ]

    finally:
        conn.close()



# mengambil lima commitment item dengan penggunaan terbesar
def get_pengusul_top5_details(user_id, budget_year, entity_id=None):

    conn = get_db_connection()

    try:
        with conn.cursor() as cursor:

            # membaca nama kolom pada tabel commitment item
            cursor.execute(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'commitment_item'
                """
            )

            columns = {row[0] for row in cursor.fetchall()}

            # memilih kolom nama yang tersedia
            name_candidates = [
                "commitment_item_name",
                "ci_name",
                "description",
                "commitment_item_description"
            ]

            name_column = next(
                (col for col in name_candidates if col in columns),
                None
            )

            # nama kolom hanya dipilih dari daftar tetap di atas
            if name_column:
                name_expression = f"MAX(ci.{name_column})"
            else:
                name_expression = "''::text"

            cursor.execute(
                f"""
                SELECT
                    ci.commitment_item_code,
                    {name_expression} AS commitment_item_name,
                    COALESCE(SUM(bm.consumable_budget), 0) AS consumable,
                    COALESCE(SUM(bm.consumed_budget), 0) AS consumed,
                    COALESCE(SUM(bm.available_amount), 0) AS available

                FROM public.budget_master bm

                JOIN public.biro b
                    ON bm.biro_id = b.biro_id
                   AND bm.entity_id = b.entity_id

                JOIN public.commitment_item ci
                    ON bm.commitment_item_id = ci.commitment_item_id

                WHERE b.biro_code = (
                    SELECT user_biro.biro_code

                    FROM public.users u

                    JOIN public.biro user_biro
                        ON u.biro_id = user_biro.biro_id
                       AND u.entity_id = user_biro.entity_id

                    WHERE u.user_id = %s
                      AND u.role = 'Pengusul'
                )

                AND bm.budget_year = %s

                AND (
                    %s::integer IS NULL
                    OR bm.entity_id = %s
                )

                GROUP BY ci.commitment_item_code

                ORDER BY consumed DESC, ci.commitment_item_code
                LIMIT 5
                """,
                (
                    user_id,
                    budget_year,
                    entity_id,
                    entity_id
                )
            )

            rows = cursor.fetchall()

        return [
            {
                "commitment_item_code": str(code),
                "commitment_item_name": str(name or ""),
                "consumable_budget": consumable,
                "consumed_budget": consumed,
                "available_amount": available
            }
            for code, name, consumable, consumed, available in rows
        ]

    finally:
        conn.close()



# mengambil seluruh detail budget pengusul berdasarkan biro, tahun, unit entity
def get_pengusul_budget_detail(user_id, budget_year, entity_id=None):

    conn = get_db_connection()

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    ci.commitment_item_code,

                    COALESCE(
                        NULLIF(TRIM(ci.commitment_item_name), ''),
                        'Nama belum tersedia'
                    ) AS commitment_item_name,

                    ue.entity_id,
                    ue.unit_entity,

                    COALESCE(
                        SUM(bm.consumable_budget), 0
                    ) AS consumable_budget,

                    COALESCE(
                        SUM(bm.consumed_budget), 0
                    ) AS consumed_budget,

                    COALESCE(
                        SUM(bm.available_amount), 0
                    ) AS available_amount,

                    CASE
                        WHEN SUM(
                            COALESCE(bm.consumable_budget, 0)
                        ) > 0
                        THEN ROUND(
                            SUM(COALESCE(bm.consumed_budget, 0))
                            * 100.0
                            / NULLIF(
                                SUM(COALESCE(bm.consumable_budget, 0)),
                                0
                            ),
                            1
                        )
                        ELSE NULL
                    END AS utilization

                FROM public.budget_master AS bm

                JOIN public.biro AS b
                    ON bm.biro_id = b.biro_id
                   AND bm.entity_id = b.entity_id

                JOIN public.commitment_item AS ci
                    ON bm.commitment_item_id = ci.commitment_item_id

                JOIN public.unit_entity AS ue
                    ON bm.entity_id = ue.entity_id

                WHERE b.biro_code = (
                    SELECT b_user.biro_code
                    FROM public.users AS u

                    JOIN public.biro AS b_user
                        ON u.biro_id = b_user.biro_id
                       AND u.entity_id = b_user.entity_id

                    WHERE u.user_id = %s
                      AND u.role = 'Pengusul'
                )

                AND bm.budget_year = %s

                AND (
                    %s::integer IS NULL
                    OR bm.entity_id = %s
                )

                GROUP BY
                    ci.commitment_item_id,
                    ci.commitment_item_code,
                    ci.commitment_item_name,
                    ue.entity_id,
                    ue.unit_entity

                ORDER BY
                    utilization DESC NULLS LAST,
                    consumed_budget DESC,
                    ci.commitment_item_code ASC,
                    ue.unit_entity ASC
                """,
                (
                    user_id,
                    budget_year,
                    entity_id,
                    entity_id
                )
            )

            rows = cursor.fetchall()

        budget_details = []

        for row in rows:
            (
                ci_code,
                ci_name,
                entity_id_result,
                unit_entity,
                consumable,
                consumed,
                available,
                utilization
            ) = row

            budget_details.append({
                "commitment_item_code": str(ci_code),
                "commitment_item_name": str(ci_name),
                "entity_id": entity_id_result,
                "unit_entity": str(unit_entity),
                "consumable_budget": consumable,
                "consumed_budget": consumed,
                "available_amount": available,
                "utilization": (
                    float(utilization)
                    if utilization is not None
                    else None
                )
            })

        return budget_details

    finally:
        conn.close()


# dashboard berdasarkan role
@app.route("/dashboard")
def dashboard():

    if not session.get("user_id"):
        flash("Silakan login terlebih dahulu.", "danger")
        return redirect(url_for("login"))

    role = session.get("role")

    if role == "Approval":
        return render_template(
            "dashboard_approval.html",
            username=session.get("username")
        )

    if role != "Pengusul":
        session.clear()
        return redirect(url_for("login"))

    user_id = session["user_id"]

    try:
        # daftar periode yang tersedia
        budget_years = get_budget_years(user_id)

        if not budget_years:
            flash(
                "Data budget untuk Biro ini belum tersedia.",
                "warning"
            )
            return redirect(url_for("profil"))

        # filter tahun
        selected_year = request.args.get("year", type=int)

        if selected_year not in budget_years:
            selected_year = budget_years[0]

        # daftar entity sesuai kode biro
        entity_options = get_pengusul_entity_options(user_id)

        # filter entity
        selected_entity_id = request.args.get(
            "entity_id",
            "all"
        )

        allowed_entity_ids = {
            str(item["entity_id"])
            for item in entity_options
        }

        if selected_entity_id != "all":
            if selected_entity_id not in allowed_entity_ids:
                flash("Unit Entity tidak valid.", "danger")
                return redirect(url_for("dashboard"))

        # ubah entity id menjadi integer atau none
        entity_filter = (
            None
            if selected_entity_id == "all"
            else int(selected_entity_id)
        )

        # ringkasan budget
        budget_summary = get_pengusul_budget_summary(
            user_id,
            selected_year,
            entity_filter
        )

        # mengambil lima commitment item terbesar
        top5_details = get_pengusul_top5_details(
            user_id,
            selected_year,
            entity_filter
        )


        return render_template(
            "dashboard_pengusul.html",
            username=session.get("username"),
            budget_summary=budget_summary,
            budget_years=budget_years,
            selected_year=selected_year,
            entity_options=entity_options,
            selected_entity_id=selected_entity_id,
            top5_details=top5_details
        )

    except psycopg2.Error:
        app.logger.exception("Gagal memuat dashboard pengusul")
        flash("Dashboard gagal dimuat.", "danger")
        return redirect(url_for("profil"))



# halaman budget detail pengusul
@app.route("/budget-detail")
def budget_detail_pengusul():

    # Validasi login
    if not session.get("user_id"):
        flash(
            "Silakan login terlebih dahulu.",
            "danger"
        )
        return redirect(url_for("login"))

    # khusus role pengusul
    if session.get("role") != "Pengusul":
        return redirect(url_for("dashboard"))

    user_id = session["user_id"]

    try:

        # 1. ambil tahun yang tersedia
        budget_years = get_budget_years(user_id)

        if not budget_years:
            flash(
                "Data budget untuk Biro ini belum tersedia.",
                "warning"
            )
            return redirect(url_for("dashboard"))

        # 2. filter tahun
        selected_year = request.args.get(
            "year",
            type=int
        )

        if selected_year not in budget_years:
            selected_year = budget_years[0]

        # 3. ambil entity yang diizinkan
        entity_options = get_pengusul_entity_options(
            user_id
        )

        allowed_entity_ids = {
            str(item["entity_id"])
            for item in entity_options
        }

        # 4. filter unit entity
        selected_entity_id = request.args.get(
            "entity_id",
            "all"
        )

        if selected_entity_id != "all":

            if selected_entity_id not in allowed_entity_ids:

                flash(
                    "Unit Entity tidak valid.",
                    "danger"
                )

                return redirect(
                    url_for("budget_detail_pengusul")
                )

        entity_filter = (
            None
            if selected_entity_id == "all"
            else int(selected_entity_id)
        )

        # 5. ambil detail budget
        budget_details = get_pengusul_budget_detail(
            user_id,
            selected_year,
            entity_filter
        )

        # 6. tampilkan halaman
        return render_template(
            "budget_detail_pengusul.html",
            username=session.get("username"),
            budget_details=budget_details,
            budget_years=budget_years,
            selected_year=selected_year,
            entity_options=entity_options,
            selected_entity_id=selected_entity_id
        )

    except psycopg2.Error:

        app.logger.exception(
            "Gagal memuat Budget Detail Pengusul"
        )

        flash(
            "Data Budget Detail gagal dimuat.",
            "danger"
        )

        return redirect(url_for("dashboard"))


# ============================================================
# PENGAJUAN BUDGET - MAPPING, LOOKUP, SHORTAGE, PENDING
# ============================================================
# Pengiriman request tidak mengubah budget_master.
# Waktu request_date dicatat saat submit. Tanggal transaksi yang
# dipilih pengguna saat ini digunakan untuk menentukan budget_year;
# jika perlu disimpan terpisah, tambah kolom transaction_date.


class PengajuanValidationError(Exception):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.status_code = status_code


def pengajuan_csrf_token():
    if "pengajuan_csrf" not in session:
        session["pengajuan_csrf"] = secrets.token_urlsafe(32)
    return session["pengajuan_csrf"]


def pengajuan_api_guard():
    if not session.get("user_id"):
        return jsonify({"error": "Silakan login terlebih dahulu."}), 401
    if session.get("role") != "Pengusul":
        return jsonify({"error": "Akses ditolak."}), 403
    if request.method == "POST":
        expected = session.get("pengajuan_csrf", "")
        supplied = request.headers.get("X-CSRFToken", "")
        if not expected or not supplied or not hmac.compare_digest(expected, supplied):
            return jsonify({"error": "Token keamanan tidak valid. Muat ulang halaman."}), 403
    return None


def pengajuan_parse_amount(raw):
    try:
        value = Decimal(str(raw).strip())
    except (InvalidOperation, TypeError, ValueError):
        raise PengajuanValidationError("Nominal pengajuan tidak valid.")
    if not value.is_finite() or value <= 0 or value != value.to_integral_value():
        raise PengajuanValidationError("Nominal harus berupa Rupiah bulat positif.")
    if value > Decimal("999999999999999"):
        raise PengajuanValidationError("Nominal terlalu besar.")
    return value


def pengajuan_parse_input(payload, require_details=False):
    if not isinstance(payload, dict):
        raise PengajuanValidationError("Format data pengajuan tidak valid.")
    try:
        entity_id = int(payload.get("entity_id"))
    except (TypeError, ValueError):
        raise PengajuanValidationError("Unit Entity wajib dipilih.")
    if entity_id <= 0:
        raise PengajuanValidationError("Unit Entity tidak valid.")
    inputs = {
        "profit_center": str(payload.get("profit_center") or "").strip(),
        "cost_center": str(payload.get("cost_center") or "").strip(),
        "gl_account": str(payload.get("gl_account") or "").strip(),
    }
    if any(not value or len(value) > 100 for value in inputs.values()):
        raise PengajuanValidationError("Pilih kode Profit Center, Cost Center, dan GL Account yang valid.")
    try:
        transaction_date = date.fromisoformat(str(payload.get("tanggal", "")))
    except (TypeError, ValueError):
        raise PengajuanValidationError("Tanggal transaksi tidak valid.")
    if not 2000 <= transaction_date.year <= 2100:
        raise PengajuanValidationError("Tahun transaksi tidak valid.")
    result = {
        "entity_id": entity_id,
        "transaction_date": transaction_date,
        "request_amount": pengajuan_parse_amount(payload.get("request_amount")),
        **inputs,
    }
    if require_details:
        pic = str(payload.get("pic") or "").strip()
        description = str(payload.get("keterangan") or "").strip()
        if not pic or len(pic) > 150:
            raise PengajuanValidationError("PIC wajib diisi, maksimal 150 karakter.")
        if not description or len(description) > 2000:
            raise PengajuanValidationError("Keterangan wajib diisi, maksimal 2000 karakter.")
        result.update(pic=pic, description=description)
    return result


def pengajuan_get_biro(cursor, user_id, entity_id):
    # Id biro akun dapat merujuk satu entity saja, tetapi akses lintas
    # entity di aplikasi ini didasarkan pada kode biro yang sama.
    cursor.execute("""
        SELECT b_target.biro_id, b_target.entity_id, b_target.biro_code
        FROM public.users u
        JOIN public.biro b_user
          ON b_user.biro_id = u.biro_id AND b_user.entity_id = u.entity_id
        JOIN public.biro b_target ON b_target.biro_code = b_user.biro_code
        WHERE u.user_id = %s AND u.role = 'Pengusul'
          AND b_target.entity_id = %s
        ORDER BY b_target.biro_id
        LIMIT 2
    """, (user_id, entity_id))
    rows = cursor.fetchall()
    if not rows:
        raise PengajuanValidationError("Unit Entity tidak termasuk akses biro Anda.", 403)
    if len(rows) != 1:
        raise PengajuanValidationError("Data biro pada Entity ambigu. Hubungi administrator.", 409)
    return rows[0]


def pengajuan_get_mapping(cursor, data):
    queries = (
        ("fund", """
            SELECT mf.target_fund_id AS id, f.fund_code AS code
            FROM public.master_fund mf
            JOIN public.fund f ON f.fund_id = mf.target_fund_id
            WHERE mf.from_profit_center = %s LIMIT 2
        """, data["profit_center"]),
        ("funds_center", """
            SELECT mfc.target_funds_center_id AS id, fc.funds_center_code AS code
            FROM public.master_fc mfc
            JOIN public.funds_center fc
              ON fc.funds_center_id = mfc.target_funds_center_id
            WHERE mfc.from_cost_center = %s LIMIT 2
        """, data["cost_center"]),
        ("commitment_item", """
            SELECT mci.target_commitment_item_id AS id,
                   ci.commitment_item_code AS code,
                   ci.commitment_item_name AS name
            FROM public.master_ci mci
            JOIN public.commitment_item ci
              ON ci.commitment_item_id = mci.target_commitment_item_id
            WHERE mci.from_gl_account = %s LIMIT 2
        """, data["gl_account"]),
    )
    mapped = {}
    missing = []
    for key, sql, input_value in queries:
        cursor.execute(sql, (input_value,))
        rows = cursor.fetchall()
        if len(rows) > 1:
            raise PengajuanValidationError("Mapping master ambigu: " + key, 409)
        if not rows:
            missing.append(key)
        else:
            mapped[key] = rows[0]
    if missing:
        raise PengajuanValidationError("Mapping tidak ditemukan: " + ", ".join(missing), 422)
    return mapped


def pengajuan_public_mapping(mapped):
    return {
        "mapping_status": "Mapped",
        "mapped_fund": {"id": mapped["fund"]["id"], "code": mapped["fund"]["code"]},
        "mapped_funds_center": {
            "id": mapped["funds_center"]["id"],
            "code": mapped["funds_center"]["code"],
        },
        "mapped_commitment_item": {
            "id": mapped["commitment_item"]["id"],
            "code": mapped["commitment_item"]["code"],
            "name": mapped["commitment_item"]["name"] or "Nama belum tersedia",
        },
    }


def pengajuan_find_budget(cursor, biro_id, entity_id, budget_year, mapped):
    common = (biro_id, entity_id, budget_year, mapped["commitment_item"]["id"])
    base = """
        SELECT bm.budget_id, bm.budget_scope, bm.current_budget,
               bm.consumable_budget, bm.consumed_budget, bm.available_amount
        FROM public.budget_master bm
        WHERE bm.biro_id = %s AND bm.entity_id = %s
          AND bm.budget_year = %s AND bm.commitment_item_id = %s
    """
    cursor.execute(base + """
        AND bm.funds_center_id = %s AND UPPER(bm.budget_scope) = 'FC_CI'
        LIMIT 2
    """, common + (mapped["funds_center"]["id"],))
    rows = cursor.fetchall()
    if len(rows) > 1:
        raise PengajuanValidationError("Sumber budget FC_CI ambigu.", 409)
    if rows:
        return rows[0]
    cursor.execute(base + """
        AND UPPER(bm.budget_scope) = 'CI_ONLY'
        LIMIT 2
    """, common)
    rows = cursor.fetchall()
    if len(rows) > 1:
        raise PengajuanValidationError("Sumber budget CI_ONLY ambigu.", 409)
    return rows[0] if rows else None


def pengajuan_check(cursor, user_id, data):
    biro = pengajuan_get_biro(cursor, user_id, data["entity_id"])
    mapped = pengajuan_get_mapping(cursor, data)
    budget = pengajuan_find_budget(
        cursor, biro["biro_id"], data["entity_id"],
        data["transaction_date"].year, mapped,
    )
    if budget is None:
        return {
            "mapped": mapped,
            "budget": None,
            "shortage": None,
            "budget_status": "Not Found",
            "message": "Sumber budget tidak ditemukan untuk kombinasi ini.",
        }
    if budget["available_amount"] is None:
        raise PengajuanValidationError("Available Amount pada sumber budget belum tersedia.", 422)
    available = Decimal(str(budget["available_amount"]))
    shortage = max(Decimal("0"), data["request_amount"] - available)
    return {
        "mapped": mapped,
        "budget": budget,
        "shortage": shortage,
        "budget_status": "Insufficient" if shortage > 0 else "Sufficient",
        "message": (
            "Budget kurang; pengajuan tetap dapat direview Approval."
            if shortage > 0 else
            "Budget mencukupi; pengajuan dapat direview Approval."
        ),
    }


@app.route("/pengajuan-budget", methods=["GET"])
def pengajuan_budget():
    if not session.get("user_id"):
        flash("Silakan login terlebih dahulu.", "danger")
        return redirect(url_for("login"))
    if session.get("role") != "Pengusul":
        return redirect(url_for("dashboard"))
    try:
        return render_template(
            "pengajuan_budget_pengusul.html",
            username=session.get("username", ""),
            entity_options=get_pengusul_entity_options(session["user_id"]),
            csrf_token=pengajuan_csrf_token(),
        )
    except psycopg2.Error:
        app.logger.exception("Gagal memuat Pengajuan Budget")
        flash("Halaman Pengajuan Budget gagal dimuat.", "danger")
        return redirect(url_for("dashboard"))


@app.route("/api/pengajuan/master-options", methods=["GET"])
def pengajuan_master_options():
    guard = pengajuan_api_guard()
    if guard is not None:
        return guard
    master_type = request.args.get("type", "").strip()
    keyword = request.args.get("q", "").strip()
    config = {
        "fund": ("master_fund", "from_profit_center"),
        "fc": ("master_fc", "from_cost_center"),
        "ci": ("master_ci", "from_gl_account"),
    }
    if master_type not in config:
        return jsonify({"error": "Jenis master tidak valid."}), 400
    if len(keyword) < 2:
        return jsonify({"results": []})
    if len(keyword) > 100:
        return jsonify({"error": "Kata pencarian terlalu panjang."}), 400
    table, column = config[master_type]  # whitelist, bukan input bebas
    sql = f"""
        SELECT DISTINCT {column} AS code FROM public.{table}
        WHERE {column} ILIKE %s ORDER BY code LIMIT 30
    """
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(sql, (f"%{keyword}%",))
            rows = cursor.fetchall()
        return jsonify({"results": [
            {"id": row["code"], "text": row["code"]} for row in rows
        ]})
    except psycopg2.Error:
        app.logger.exception("Gagal memuat Master Mapping")
        return jsonify({"error": "Data master gagal dimuat."}), 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/api/pengajuan/mapping", methods=["POST"])
def pengajuan_mapping():
    guard = pengajuan_api_guard()
    if guard is not None:
        return guard
    payload = request.get_json(silent=True) or {}
    data = {
        "profit_center": str(payload.get("profit_center") or "").strip(),
        "cost_center": str(payload.get("cost_center") or "").strip(),
        "gl_account": str(payload.get("gl_account") or "").strip(),
    }
    if any(not v or len(v) > 100 for v in data.values()):
        return jsonify({"error": "Semua kode master harus valid."}), 400
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            mapped = pengajuan_get_mapping(cursor, data)
        return jsonify(pengajuan_public_mapping(mapped))
    except PengajuanValidationError as exc:
        return jsonify({"error": str(exc), "mapping_status": "Not Found"}), exc.status_code
    except psycopg2.Error:
        app.logger.exception("Gagal mapping")
        return jsonify({"error": "Mapping gagal diproses."}), 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/api/pengajuan/shortage", methods=["POST"])
def pengajuan_shortage():
    guard = pengajuan_api_guard()
    if guard is not None:
        return guard
    conn = None
    try:
        data = pengajuan_parse_input(request.get_json(silent=True) or {})
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            result = pengajuan_check(cursor, session["user_id"], data)
        return jsonify({
            "budget_found": result["budget"] is not None,
            "budget_status": result["budget_status"],
            "shortage_amount": str(result["shortage"]) if result["shortage"] is not None else None,
            "message": result["message"],
        })
    except PengajuanValidationError as exc:
        return jsonify({"error": str(exc), "shortage_amount": None}), exc.status_code
    except psycopg2.Error:
        app.logger.exception("Gagal hitung shortage")
        return jsonify({"error": "Shortage gagal dihitung."}), 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/api/pengajuan/periksa", methods=["POST"])
def pengajuan_periksa():
    guard = pengajuan_api_guard()
    if guard is not None:
        return guard
    conn = None
    try:
        data = pengajuan_parse_input(
            request.get_json(silent=True) or {}, require_details=True
        )
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            result = pengajuan_check(cursor, session["user_id"], data)
        return jsonify({
            **pengajuan_public_mapping(result["mapped"]),
            "budget_found": result["budget"] is not None,
            "budget_scope": result["budget"]["budget_scope"] if result["budget"] else None,
            "budget_status": result["budget_status"],
            "shortage_amount": str(result["shortage"]) if result["shortage"] is not None else None,
            "can_submit": result["budget"] is not None,
            "message": result["message"],
        })
    except PengajuanValidationError as exc:
        return jsonify({"error": str(exc), "can_submit": False}), exc.status_code
    except psycopg2.Error:
        app.logger.exception("Gagal periksa budget")
        return jsonify({"error": "Pemeriksaan budget gagal."}), 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/api/pengajuan/submit", methods=["POST"])
def pengajuan_submit():
    guard = pengajuan_api_guard()
    if guard is not None:
        return guard
    # Penyimpanan lampiran belum diimplementasikan. Tolak apabila dikirim.
    if request.files:
        return jsonify({"error": "Upload lampiran belum tersedia."}), 422
    payload = request.get_json(silent=True) or {}
    if payload.get("lampiran") or payload.get("attachment"):
        return jsonify({"error": "Upload lampiran belum tersedia."}), 422
    conn = None
    try:
        data = pengajuan_parse_input(payload, require_details=True)
        conn = get_db_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                result = pengajuan_check(cursor, session["user_id"], data)
                budget = result["budget"]
                if budget is None:
                    raise PengajuanValidationError(
                        "Sumber budget tidak ditemukan. Pengajuan belum dapat dikirim.", 422
                    )
                current = budget["current_budget"]
                consumable = budget["consumable_budget"]
                approval_hold = (
                    Decimal(str(current)) - Decimal(str(consumable))
                    if current is not None and consumable is not None else None
                )
                cursor.execute("""
                    INSERT INTO public.budget_request (
                        user_id, entity_id, request_date, pic,
                        input_profit_center, input_cost_center, input_gl_account,
                        request_amount, request_description,
                        mapped_fund_id, mapped_funds_center_id,
                        mapped_commitment_item_id, budget_id, budget_scope,
                        available_amount_snapshot, shortage_amount,
                        approval_hold_amount_snapshot,
                        mapping_status, budget_status, request_status
                    ) VALUES (
                        %s, %s, NOW(), %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, 'Mapped', %s, 'Pending'
                    ) RETURNING request_id
                """, (
                    session["user_id"], data["entity_id"], data["pic"],
                    data["profit_center"], data["cost_center"], data["gl_account"],
                    data["request_amount"], data["description"],
                    result["mapped"]["fund"]["id"],
                    result["mapped"]["funds_center"]["id"],
                    result["mapped"]["commitment_item"]["id"],
                    budget["budget_id"], budget["budget_scope"],
                    budget["available_amount"], result["shortage"],
                    approval_hold, result["budget_status"],
                ))
                saved = cursor.fetchone()
        return jsonify({
            "success": True,
            "request_id": saved["request_id"],
            "request_status": "Pending",
            "budget_status": result["budget_status"],
            "message": "Pengajuan berhasil dikirim untuk review Approval.",
        }), 201
    except PengajuanValidationError as exc:
        if conn is not None:
            conn.rollback()
        return jsonify({"success": False, "error": str(exc)}), exc.status_code
    except psycopg2.Error:
        if conn is not None:
            conn.rollback()
        app.logger.exception("Gagal menyimpan pengajuan")
        return jsonify({"success": False, "error": "Pengajuan gagal disimpan."}), 500
    finally:
        if conn is not None:
            conn.close()

# halaman riwayat pengajuan
def format_rupiah_riwayat(value):
    if value is None:
        return "—"

    return "Rp" + f"{value:,.0f}".replace(",", ".")


@app.route("/riwayat-pengajuan", methods=["GET"])
def riwayat_pengajuan_pengusul():

    if not session.get("user_id"):
        flash("Silakan login terlebih dahulu.", "danger")
        return redirect(url_for("login"))

    if session.get("role") != "Pengusul":
        flash("Halaman hanya untuk Pengusul.", "danger")
        return redirect(url_for("dashboard"))

    user_id = session["user_id"]

    keyword = request.args.get(
        "q", ""
    ).strip()[:100]

    selected_status = request.args.get(
        "status", ""
    ).strip()[:50]

    page = request.args.get(
        "page", 1, type=int
    )

    page = max(1, page)

    per_page = 10

    conn = None

    try:
        conn = get_db_connection()

        with conn.cursor(
            cursor_factory=RealDictCursor
        ) as cursor:

            # --------------------------------------------
            # RINGKASAN SELURUH PENGAJUAN PENGGUNA
            # --------------------------------------------

            cursor.execute(
                """
                SELECT
                    COUNT(*) AS total,

                    COUNT(*) FILTER (
                        WHERE LOWER(request_status) = 'pending'
                    ) AS pending,

                    COUNT(*) FILTER (
                        WHERE LOWER(request_status) = 'approved'
                    ) AS approved,

                    COUNT(*) FILTER (
                        WHERE LOWER(request_status) = 'rejected'
                    ) AS rejected

                FROM public.budget_request

                WHERE user_id = %s
                """,
                (user_id,)
            )

            summary = cursor.fetchone()

            # --------------------------------------------
            # PILIHAN STATUS BERDASARKAN DATA AKTUAL
            # --------------------------------------------

            cursor.execute(
                """
                SELECT DISTINCT request_status
                FROM public.budget_request
                WHERE user_id = %s
                  AND request_status IS NOT NULL
                ORDER BY request_status
                """,
                (user_id,)
            )

            status_options = [
                row["request_status"]
                for row in cursor.fetchall()
            ]

            if (
                selected_status
                and selected_status not in status_options
            ):
                selected_status = ""

            # --------------------------------------------
            # FILTER DATA
            # --------------------------------------------

            conditions = [
                "br.user_id = %s"
            ]

            params = [user_id]

            if selected_status:
                conditions.append(
                    "br.request_status = %s"
                )
                params.append(selected_status)

            if keyword:
                conditions.append(
                    """
                    (
                        br.request_id::text ILIKE %s
                        OR br.pic ILIKE %s
                        OR br.request_description ILIKE %s
                    )
                    """
                )

                search = f"%{keyword}%"

                params.extend([
                    search,
                    search,
                    search
                ])

            where_sql = " AND ".join(conditions)

            # --------------------------------------------
            # HITUNG DATA UNTUK PAGINATION
            # --------------------------------------------

            cursor.execute(
                f"""
                SELECT COUNT(*) AS total
                FROM public.budget_request br
                WHERE {where_sql}
                """,
                params
            )

            total_rows = cursor.fetchone()["total"]

            total_pages = max(
                1,
                (total_rows + per_page - 1) // per_page
            )

            page = min(page, total_pages)

            offset = (page - 1) * per_page

            # --------------------------------------------
            # DATA RIWAYAT
            # --------------------------------------------

            cursor.execute(
                f"""
                SELECT
                    br.request_id,
                    br.entity_id,

                    br.request_date
                        AT TIME ZONE 'Asia/Jakarta'
                        AS request_date_local,

                    br.pic,
                    br.input_profit_center,
                    br.input_cost_center,
                    br.input_gl_account,

                    br.request_amount,
                    br.request_description,

                    br.mapping_status,
                    br.budget_status,
                    br.request_status,

                    br.budget_scope,
                    br.shortage_amount,

                    ue.unit_entity,

                    f.fund_code AS mapped_fund_code,

                    fc.funds_center_code
                        AS mapped_fc_code,

                    ci.commitment_item_code
                        AS mapped_ci_code,

                    ci.commitment_item_name
                        AS mapped_ci_name

                FROM public.budget_request br

                LEFT JOIN public.unit_entity ue
                  ON br.entity_id = ue.entity_id

                LEFT JOIN public.fund f
                  ON br.mapped_fund_id = f.fund_id

                LEFT JOIN public.funds_center fc
                  ON br.mapped_funds_center_id =
                     fc.funds_center_id

                LEFT JOIN public.commitment_item ci
                  ON br.mapped_commitment_item_id =
                     ci.commitment_item_id

                WHERE {where_sql}

                ORDER BY
                    br.request_date DESC,
                    br.request_id DESC

                LIMIT %s OFFSET %s
                """,
                params + [per_page, offset]
            )

            history_rows = cursor.fetchall()

        return render_template(
            "riwayat_pengajuan_pengusul.html",

            username=session.get("username", ""),

            history_rows=history_rows,
            summary=summary,

            keyword=keyword,
            selected_status=selected_status,
            status_options=status_options,

            page=page,
            total_pages=total_pages,
            total_rows=total_rows,

            format_rupiah=format_rupiah_riwayat
        )

    except psycopg2.Error:
        app.logger.exception(
            "Gagal memuat Riwayat Pengajuan"
        )

        flash(
            "Riwayat Pengajuan belum dapat dimuat.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    finally:
        if conn is not None:
            conn.close()


# logout pengguna
@app.route("/logout", methods=["POST"])
def logout():

    session.clear()

    flash("Berhasil logout.", "info")

    return redirect(url_for("login"))


# menjalankan aplikasi flask lokal
if __name__ == "__main__":
    app.run(debug=True, port=5001)