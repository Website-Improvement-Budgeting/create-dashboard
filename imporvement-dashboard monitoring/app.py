import os
import hmac

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


# halaman pengajuan budget

@app.route("/pengajuan-budget", methods=["GET"])
def pengajuan_budget():

    if not session.get("user_id"):
        flash("Silakan login terlebih dahulu.", "danger")
        return redirect(url_for("login"))

    if session.get("role") != "Pengusul":
        flash("Halaman hanya untuk Pengusul.", "danger")
        return redirect(url_for("dashboard"))

    user_id = session["user_id"]

    try:
        entity_options = get_pengusul_entity_options(user_id)

        return render_template(
            "pengajuan_budget_pengusul.html",
            username=session.get("username", ""),
            entity_options=entity_options
        )

    except Exception:
        app.logger.exception(
            "Gagal memuat halaman Pengajuan Budget"
        )

        flash(
            "Halaman Pengajuan Budget belum dapat dimuat.",
            "danger"
        )

        return redirect(url_for("dashboard"))


# pengajuan master options
@app.route("/api/pengajuan/master-options", methods=["GET"])
def pengajuan_master_options():

    if not session.get("user_id"):
        return jsonify({"error": "Unauthorized"}), 401

    if session.get("role") != "Pengusul":
        return jsonify({"error": "Forbidden"}), 403

    master_type = request.args.get("type", "").strip()
    keyword = request.args.get("q", "").strip()

    config = {
        "fund": {
            "table": "master_fund",
            "column": "from_profit_center"
        },
        "fc": {
            "table": "master_fc",
            "column": "from_cost_center"
        },
        "ci": {
            "table": "master_ci",
            "column": "from_gl_account"
        }
    }

    if master_type not in config:
        return jsonify({
            "error": "Tipe master tidak valid"
        }), 400

    setting = config[master_type]

    sql = f"""
        SELECT DISTINCT
            {setting['column']} AS code
        FROM public.{setting['table']}
        WHERE {setting['column']} ILIKE %s
        ORDER BY code
        LIMIT 30
    """

    conn = None

    try:
        conn = get_db_connection()

        with conn.cursor(
            cursor_factory=RealDictCursor
        ) as cursor:

            cursor.execute(
                sql,
                (f"%{keyword}%",)
            )

            rows = cursor.fetchall()

        return jsonify({
            "results": [
                {
                    "id": row["code"],
                    "text": row["code"]
                }
                for row in rows
            ]
        })

    except Exception:
        app.logger.exception(
            "Gagal mengambil pilihan master"
        )

        return jsonify({
            "error": "Data master belum dapat dimuat"
        }), 500

    finally:
        if conn:
            conn.close()


# pengajuan mapping

@app.route("/api/pengajuan/mapping", methods=["POST"])
def pengajuan_mapping():

    if not session.get("user_id"):
        return jsonify({"error": "Unauthorized"}), 401

    if session.get("role") != "Pengusul":
        return jsonify({"error": "Forbidden"}), 403

    data = request.get_json(silent=True) or {}

    profit_center = str(
        data.get("profit_center") or ""
    ).strip()

    cost_center = str(
        data.get("cost_center") or ""
    ).strip()

    gl_account = str(
        data.get("gl_account") or ""
    ).strip()

    if not all([
        profit_center,
        cost_center,
        gl_account
    ]):
        return jsonify({
            "error": "Semua kode harus diisi"
        }), 400

    conn = None

    try:
        conn = get_db_connection()

        with conn.cursor(
            cursor_factory=RealDictCursor
        ) as cursor:

            cursor.execute("""
                SELECT
                    mf.target_fund_id AS id,
                    f.fund_code AS code
                FROM public.master_fund mf
                JOIN public.fund f
                  ON f.fund_id = mf.target_fund_id
                WHERE mf.from_profit_center = %s
            """, (profit_center,))

            mapped_fund = cursor.fetchone()

            cursor.execute("""
                SELECT
                    mf.target_funds_center_id AS id,
                    fc.funds_center_code AS code
                FROM public.master_fc mf
                JOIN public.funds_center fc
                  ON fc.funds_center_id =
                     mf.target_funds_center_id
                WHERE mf.from_cost_center = %s
            """, (cost_center,))

            mapped_fc = cursor.fetchone()

            cursor.execute("""
                SELECT
                    mc.target_commitment_item_id AS id,
                    ci.commitment_item_code AS code,
                    ci.commitment_item_name AS name
                FROM public.master_ci mc
                JOIN public.commitment_item ci
                  ON ci.commitment_item_id =
                     mc.target_commitment_item_id
                WHERE mc.from_gl_account = %s
            """, (gl_account,))

            mapped_ci = cursor.fetchone()

        missing = []

        if not mapped_fund:
            missing.append("Profit Center")

        if not mapped_fc:
            missing.append("Cost Center")

        if not mapped_ci:
            missing.append("GL Account")

        if missing:
            return jsonify({
                "mapping_status": "Not Found",
                "missing": missing,
                "message": (
                    "Mapping tidak ditemukan: " +
                    ", ".join(missing)
                )
            }), 422

        return jsonify({
            "mapping_status": "Mapped",
            "mapped_fund": mapped_fund,
            "mapped_funds_center": mapped_fc,
            "mapped_commitment_item": mapped_ci
        })

    except Exception:
        app.logger.exception(
            "Gagal melakukan mapping pengajuan"
        )

        return jsonify({
            "error": "Pemeriksaan mapping gagal"
        }), 500

    finally:
        if conn:
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