import os
import hmac
import secrets
from datetime import date
from decimal import Decimal, InvalidOperation

from io import BytesIO
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Border, Side, Alignment
from openpyxl.utils import get_column_letter
from openpyxl.comments import Comment
from flask import send_file

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

    if role == "Approval":
        return redirect(url_for("profil_approval"))

    return redirect(url_for("login"))


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


# =========================================================
# DASHBOARD BUDGETING APPROVAL - DATA NRM
# Fungsi terpisah, tidak mengubah fungsi Pengusul
# =========================================================

def get_approval_budget_options():

    conn = get_db_connection()

    try:
        with conn.cursor() as cursor:

            cursor.execute("""
                SELECT DISTINCT budget_year
                FROM public.budget_master
                WHERE budget_year IS NOT NULL
                ORDER BY budget_year DESC
            """)
            years = [row[0] for row in cursor.fetchall()]

            cursor.execute("""
                SELECT entity_id, unit_entity
                FROM public.unit_entity
                ORDER BY unit_entity
            """)
            entities = [
                {"id": row[0], "name": row[1]}
                for row in cursor.fetchall()
            ]

            cursor.execute("""
                SELECT DISTINCT
                    b.biro_id,
                    b.entity_id,
                    b.biro_code,
                    b.biro_name,
                    ue.unit_entity
                FROM public.biro b
                LEFT JOIN public.unit_entity ue
                    ON b.entity_id = ue.entity_id
                ORDER BY ue.unit_entity, b.biro_code
            """)
            biros = [
                {
                    "id": row[0],
                    "entity_id": row[1],
                    "code": row[2],
                    "name": row[3],
                    "entity": row[4]
                }
                for row in cursor.fetchall()
            ]

            cursor.execute("""
                SELECT DISTINCT
                    funds_center_id,
                    funds_center_code
                FROM public.funds_center
                WHERE funds_center_id IS NOT NULL
                ORDER BY funds_center_code
            """)
            funds_centers = [
                {"id": row[0], "code": row[1]}
                for row in cursor.fetchall()
            ]

            cursor.execute("""
                SELECT
                    commitment_item_id,
                    commitment_item_code
                FROM public.commitment_item
                ORDER BY commitment_item_code
            """)
            commitment_items = [
                {"id": row[0], "code": row[1]}
                for row in cursor.fetchall()
            ]

        return {
            "years": years,
            "entities": entities,
            "biros": biros,
            "funds_centers": funds_centers,
            "commitment_items": commitment_items
        }

    finally:
        conn.close()


def get_approval_budget_data(
    budget_year,
    budget_scope="all",
    entity_id="all",
    funds_center_id="all",
    commitment_item_id="all",
    biro_id="all"
):
    """
    Mengambil ringkasan dan analisis budget Approval.
    Agregasi disediakan untuk Entity, Biro, Funds Center, dan Commitment Item.
    Seluruh agregasi mengikuti filter tahun, scope, entity, funds center, CI, dan biro.
    """
    conn = get_db_connection()

    try:
        with conn.cursor() as cursor:
            where_sql = """
                WHERE bm.budget_year = %s
                  AND (%s = 'all' OR bm.budget_scope = %s)
                  AND (%s = 'all' OR bm.entity_id::text = %s)
                  AND (%s = 'all' OR bm.funds_center_id::text = %s)
                  AND (%s = 'all' OR bm.commitment_item_id::text = %s)
                  AND (%s = 'all' OR bm.biro_id::text = %s)
            """
            params = (
                budget_year,
                budget_scope, budget_scope,
                entity_id, entity_id,
                funds_center_id, funds_center_id,
                commitment_item_id, commitment_item_id,
                biro_id, biro_id
            )

            # -------------------------------------------------
            # 1. KPI SUMMARY
            # -------------------------------------------------
            cursor.execute(f"""
                SELECT
                    COALESCE(SUM(bm.current_budget), 0),
                    COALESCE(SUM(bm.consumable_budget), 0),
                    COALESCE(SUM(bm.consumed_budget), 0),
                    COALESCE(SUM(bm.available_amount), 0),
                    COALESCE(
                        SUM(bm.current_budget - bm.consumable_budget), 0
                    ),
                    COUNT(*)
                FROM public.budget_master bm
                {where_sql}
            """, params)

            row = cursor.fetchone()
            summary = {
                "current_budget": float(row[0] or 0),
                "consumable_budget": float(row[1] or 0),
                "consumed_budget": float(row[2] or 0),
                "available_amount": float(row[3] or 0),
                "approval_hold": float(row[4] or 0),
                "total_records": row[5] or 0
            }

            # -------------------------------------------------
            # 2. RINGKASAN BERDASARKAN BUDGET SCOPE
            # -------------------------------------------------
            cursor.execute(f"""
                SELECT
                    bm.budget_scope,
                    COUNT(*),
                    COALESCE(SUM(bm.current_budget), 0),
                    COALESCE(SUM(bm.consumable_budget), 0),
                    COALESCE(SUM(bm.consumed_budget), 0),
                    COALESCE(SUM(bm.available_amount), 0)
                FROM public.budget_master bm
                {where_sql}
                GROUP BY bm.budget_scope
                ORDER BY bm.budget_scope
            """, params)

            scope_summary = [
                {
                    "scope": r[0],
                    "records": r[1],
                    "current": float(r[2] or 0),
                    "consumable": float(r[3] or 0),
                    "consumed": float(r[4] or 0),
                    "available": float(r[5] or 0)
                }
                for r in cursor.fetchall()
            ]

            # -------------------------------------------------
            # HELPER: FORMAT HASIL AGREGASI DIMENSI
            # -------------------------------------------------
            def serialize_dimension(rows, id_key):
                result = []
                for item_id, label, current, consumable, consumed, available, hold in rows:
                    current = float(current or 0)
                    consumable = float(consumable or 0)
                    consumed = float(consumed or 0)
                    available = float(available or 0)
                    hold = float(hold or 0)

                    utilization = (
                        consumed / consumable * 100
                        if consumable > 0 else None
                    )
                    hold_ratio = (
                        hold / current * 100
                        if current > 0 else None
                    )

                    result.append({
                        id_key: item_id,
                        "label": str(label or "Tidak diketahui"),
                        "current_budget": current,
                        "consumable_budget": consumable,
                        "consumed_budget": consumed,
                        "available_amount": available,
                        "approval_hold": hold,
                        "utilization_rate": (
                            round(utilization, 2)
                            if utilization is not None else None
                        ),
                        "approval_hold_ratio": (
                            round(hold_ratio, 2)
                            if hold_ratio is not None else None
                        )
                    })

                # Urutan utama menggunakan nominal Consumed Budget terbesar.
                # Utilization tetap disimpan sebagai indikator pendamping.
                result.sort(
                    key=lambda x: x["consumed_budget"],
                    reverse=True
                )
                return result

            # -------------------------------------------------
            # 3. AGREGASI UNIT ENTITY
            # -------------------------------------------------
            cursor.execute(f"""
                SELECT
                    bm.entity_id,
                    COALESCE(ue.unit_entity, 'Tidak diketahui'),
                    COALESCE(SUM(bm.current_budget), 0),
                    COALESCE(SUM(bm.consumable_budget), 0),
                    COALESCE(SUM(bm.consumed_budget), 0),
                    COALESCE(SUM(bm.available_amount), 0),
                    COALESCE(
                        SUM(bm.current_budget - bm.consumable_budget), 0
                    )
                FROM public.budget_master bm
                LEFT JOIN public.unit_entity ue
                    ON bm.entity_id = ue.entity_id
                {where_sql}
                GROUP BY bm.entity_id, ue.unit_entity
            """, params)
            entity_utilization = serialize_dimension(
                cursor.fetchall(), "entity_id"
            )

            # -------------------------------------------------
            # 4. AGREGASI BIRO
            # Biro dibedakan berdasarkan biro_id dan entity_id.
            # -------------------------------------------------
            cursor.execute(f"""
                SELECT
                    b.biro_id,
                    CASE
                        WHEN b.biro_code IS NOT NULL AND b.biro_name IS NOT NULL
                            THEN b.biro_code || ' - ' || b.biro_name
                        WHEN b.biro_code IS NOT NULL THEN b.biro_code
                        WHEN b.biro_name IS NOT NULL THEN b.biro_name
                        ELSE 'Biro tidak teridentifikasi'
                    END,
                    COALESCE(SUM(bm.current_budget), 0),
                    COALESCE(SUM(bm.consumable_budget), 0),
                    COALESCE(SUM(bm.consumed_budget), 0),
                    COALESCE(SUM(bm.available_amount), 0),
                    COALESCE(
                        SUM(bm.current_budget - bm.consumable_budget), 0
                    )
                FROM public.budget_master bm
                LEFT JOIN public.biro b
                    ON bm.biro_id = b.biro_id
                   AND bm.entity_id = b.entity_id
                {where_sql}
                GROUP BY
                    b.biro_id, b.entity_id, b.biro_code, b.biro_name
            """, params)
            biro_utilization = serialize_dimension(
                cursor.fetchall(), "biro_id"
            )

            # -------------------------------------------------
            # 5. AGREGASI FUNDS CENTER
            # -------------------------------------------------
            cursor.execute(f"""
                SELECT
                    fc.funds_center_id,
                    COALESCE(fc.funds_center_code, 'Tanpa Funds Center'),
                    COALESCE(SUM(bm.current_budget), 0),
                    COALESCE(SUM(bm.consumable_budget), 0),
                    COALESCE(SUM(bm.consumed_budget), 0),
                    COALESCE(SUM(bm.available_amount), 0),
                    COALESCE(
                        SUM(bm.current_budget - bm.consumable_budget), 0
                    )
                FROM public.budget_master bm
                LEFT JOIN public.funds_center fc
                    ON bm.funds_center_id = fc.funds_center_id
                {where_sql}
                GROUP BY fc.funds_center_id, fc.funds_center_code
            """, params)
            funds_center_utilization = serialize_dimension(
                cursor.fetchall(), "funds_center_id"
            )

            # -------------------------------------------------
            # 6. AGREGASI COMMITMENT ITEM
            # -------------------------------------------------
            cursor.execute(f"""
                SELECT
                    ci.commitment_item_id,
                    CASE
                        WHEN ci.commitment_item_code IS NOT NULL
                             AND ci.commitment_item_name IS NOT NULL
                            THEN ci.commitment_item_code || ' - ' || ci.commitment_item_name
                        WHEN ci.commitment_item_code IS NOT NULL
                            THEN ci.commitment_item_code
                        WHEN ci.commitment_item_name IS NOT NULL
                            THEN ci.commitment_item_name
                        ELSE 'Commitment Item tidak teridentifikasi'
                    END,
                    COALESCE(SUM(bm.current_budget), 0),
                    COALESCE(SUM(bm.consumable_budget), 0),
                    COALESCE(SUM(bm.consumed_budget), 0),
                    COALESCE(SUM(bm.available_amount), 0),
                    COALESCE(
                        SUM(bm.current_budget - bm.consumable_budget), 0
                    )
                FROM public.budget_master bm
                LEFT JOIN public.commitment_item ci
                    ON bm.commitment_item_id = ci.commitment_item_id
                {where_sql}
                GROUP BY
                    ci.commitment_item_id,
                    ci.commitment_item_code,
                    ci.commitment_item_name
            """, params)
            commitment_item_utilization = serialize_dimension(
                cursor.fetchall(), "commitment_item_id"
            )

            # -------------------------------------------------
            # 7. TOP 5 COMMITMENT ITEM BERDASARKAN CONSUMED TERBESAR
            # -------------------------------------------------
            # Ranking memakai nominal consumed_budget, bukan utilization_rate.
            top5_commitment_items = sorted(
                commitment_item_utilization,
                key=lambda item: float(item.get("consumed_budget") or 0),
                reverse=True
            )

            # -------------------------------------------------
            # 8. DATA VISUALISASI DAN KOMPATIBILITAS FRONTEND LAMA
            # -------------------------------------------------
            entity_chart = [
                {
                    "label": item["label"],
                    "value": item["consumed_budget"]
                }
                for item in entity_utilization
            ]

            funds_center_chart = [
                {
                    "label": item["label"],
                    "value": item["consumed_budget"]
                }
                for item in funds_center_utilization
            ]

            commitment_item_chart = [
                {
                    "label": item["label"],
                    "value": item["consumed_budget"]
                }
                for item in commitment_item_utilization
            ]

            # Dataset khusus untuk stacked bar Ringkasan Budget.
            # Secara konsep: Current Budget = Consumed + Available + Approval Hold.
            entity_budget_composition = [
                {
                    "label": item["label"],
                    "current_budget": item["current_budget"],
                    "consumable_budget": item["consumable_budget"],
                    "consumed_budget": item["consumed_budget"],
                    "available_amount": item["available_amount"],
                    "approval_hold": item["approval_hold"],
                    "utilization_rate": item["utilization_rate"]
                }
                for item in entity_utilization
            ]

            # -------------------------------------------------
            # 8. DETAIL BUDGET MONITORING PER ENTITY, BIRO, DAN CI
            # -------------------------------------------------
            cursor.execute(f"""
                SELECT
                    COALESCE(ue.unit_entity, 'Tidak diketahui') AS unit_entity,
                    COALESCE(b.biro_code, '-') AS biro_code,
                    COALESCE(b.biro_name, 'Biro tidak diketahui') AS biro_name,
                    COALESCE(ci.commitment_item_code::text, '-') AS commitment_item_code,
                    COALESCE(ci.commitment_item_name, 'Nama belum tersedia') AS commitment_item_name,
                    COALESCE(SUM(bm.current_budget), 0) AS current_budget,
                    COALESCE(SUM(bm.consumable_budget), 0) AS consumable_budget,
                    COALESCE(SUM(bm.consumed_budget), 0) AS consumed_budget,
                    COALESCE(SUM(bm.available_amount), 0) AS available_amount,
                    COALESCE(SUM(bm.current_budget - bm.consumable_budget), 0) AS approval_hold
                FROM public.budget_master bm
                LEFT JOIN public.unit_entity ue
                    ON bm.entity_id = ue.entity_id
                LEFT JOIN public.biro b
                    ON bm.biro_id = b.biro_id
                   AND bm.entity_id = b.entity_id
                LEFT JOIN public.commitment_item ci
                    ON bm.commitment_item_id = ci.commitment_item_id
                {where_sql}
                GROUP BY
                    ue.unit_entity,
                    b.biro_code,
                    b.biro_name,
                    ci.commitment_item_code,
                    ci.commitment_item_name
                ORDER BY SUM(bm.consumed_budget) DESC,
                         ue.unit_entity,
                         ci.commitment_item_code
            """, params)

            budget_monitoring = []
            for row in cursor.fetchall():
                current, consumable, consumed, available, hold = (
                    float(row[5] or 0),
                    float(row[6] or 0),
                    float(row[7] or 0),
                    float(row[8] or 0),
                    float(row[9] or 0)
                )
                budget_monitoring.append({
                    "unit_entity": str(row[0] or "Tidak diketahui"),
                    "biro_code": str(row[1] or "-"),
                    "biro_name": str(row[2] or "Biro tidak diketahui"),
                    "commitment_item_code": str(row[3] or "-"),
                    "commitment_item_name": str(row[4] or "Nama belum tersedia"),
                    "current_budget": current,
                    "consumable_budget": consumable,
                    "consumed_budget": consumed,
                    "available_amount": available,
                    "approval_hold": hold,
                    "utilization_rate": (
                        round(consumed / consumable * 100, 2)
                        if consumable > 0 else None
                    ),
                    "budget_release_rate": (
                        round(consumable / current * 100, 2)
                        if current > 0 else None
                    )
                })

            # -------------------------------------------------
            # 9. DATA VISUALISASI DAN KOMPATIBILITAS FRONTEND
            # -------------------------------------------------
            visualization_data = {
                # Key lama tetap dipertahankan agar frontend yang sudah ada
                # tidak langsung rusak.
                "entity": entity_chart,
                "entity_utilization": entity_utilization,
                "entity_budget_composition": entity_budget_composition,
                "budget_attention": entity_utilization,
                "funds_center": funds_center_chart,
                "commitment_item": commitment_item_chart,

                # Dataset analisis untuk tab Analisis Anggaran.
                "dimension_analysis": {
                    "entity": entity_utilization,
                    "biro": biro_utilization,
                    "funds_center": funds_center_utilization,
                    "commitment_item": commitment_item_utilization
                },
                "top5_commitment_items": top5_commitment_items,
                "budget_monitoring": budget_monitoring
            }

        return {
            "summary": summary,
            "scope_summary": scope_summary,
            "visualization_data": visualization_data
        }

    finally:
        conn.close()


# ============================================================
# BUDGET DETAIL APPROVAL
# Halaman terpisah dari Dashboard Budgetting.
# Tidak mengubah alur maupun query Budget Detail Pengusul.
# ============================================================

def get_approval_budget_detail(
    budget_year,
    budget_scope="all",
    entity_ids=None,
    biro_ids=None,
    funds_center_ids=None,
    commitment_item_ids=None,
    keyword=""
):
    """Mengambil seluruh detail budget Approval tanpa membatasi jumlah baris."""
    conn = get_db_connection()
    try:
        conditions = ["bm.budget_year = %s"]
        params = [budget_year]

        # Filter multiselect: setiap filter dapat berisi lebih dari satu ID.
        entity_ids = [str(x) for x in (entity_ids or [])]
        biro_ids = [str(x) for x in (biro_ids or [])]
        funds_center_ids = [str(x) for x in (funds_center_ids or [])]
        commitment_item_ids = [str(x) for x in (commitment_item_ids or [])]

        if budget_scope != "all":
            conditions.append("bm.budget_scope = %s")
            params.append(budget_scope)
        if entity_ids:
            conditions.append("bm.entity_id::text = ANY(%s)")
            params.append(entity_ids)
        if biro_ids:
            conditions.append("bm.biro_id::text = ANY(%s)")
            params.append(biro_ids)
        if funds_center_ids:
            conditions.append("bm.funds_center_id::text = ANY(%s)")
            params.append(funds_center_ids)
        if commitment_item_ids:
            conditions.append("bm.commitment_item_id::text = ANY(%s)")
            params.append(commitment_item_ids)

        if keyword:
            conditions.append("""(
                COALESCE(ue.unit_entity, '') ILIKE %s
                OR COALESCE(b.biro_code, '') ILIKE %s
                OR COALESCE(b.biro_name, '') ILIKE %s
                OR COALESCE(fc.funds_center_code, '') ILIKE %s
                OR COALESCE(ci.commitment_item_code, '') ILIKE %s
                OR COALESCE(ci.commitment_item_name, '') ILIKE %s
                OR COALESCE(bm.budget_scope, '') ILIKE %s
                OR bm.budget_id::text ILIKE %s
            )""")
            pattern = f"%{keyword}%"
            params.extend([pattern] * 8)

        where_sql = " WHERE " + " AND ".join(conditions)

        with conn.cursor() as cursor:
            cursor.execute(f"""
                SELECT COUNT(*)
                FROM public.budget_master bm
                LEFT JOIN public.unit_entity ue
                    ON bm.entity_id = ue.entity_id
                LEFT JOIN public.biro b
                    ON bm.biro_id = b.biro_id
                   AND bm.entity_id = b.entity_id
                LEFT JOIN public.funds_center fc
                    ON bm.funds_center_id = fc.funds_center_id
                LEFT JOIN public.commitment_item ci
                    ON bm.commitment_item_id = ci.commitment_item_id
                {where_sql}
            """, params)
            total_rows = cursor.fetchone()[0] or 0

            # Ambil SEMUA baris yang sesuai filter. Pagination dilakukan di browser.
            cursor.execute(f"""
                SELECT
                    bm.budget_id,
                    ue.unit_entity,
                    bm.budget_scope,
                    b.biro_code,
                    b.biro_name,
                    fc.funds_center_code,
                    ci.commitment_item_code,
                    ci.commitment_item_name,
                    bm.current_budget,
                    bm.consumable_budget,
                    bm.consumed_budget,
                    bm.available_amount,
                    CASE
                        WHEN COALESCE(bm.consumable_budget, 0) > 0
                        THEN ROUND(
                            COALESCE(bm.consumed_budget, 0) * 100.0
                            / NULLIF(bm.consumable_budget, 0), 1
                        )
                        ELSE NULL
                    END AS utilization
                FROM public.budget_master bm
                LEFT JOIN public.unit_entity ue
                    ON bm.entity_id = ue.entity_id
                LEFT JOIN public.biro b
                    ON bm.biro_id = b.biro_id
                   AND bm.entity_id = b.entity_id
                LEFT JOIN public.funds_center fc
                    ON bm.funds_center_id = fc.funds_center_id
                LEFT JOIN public.commitment_item ci
                    ON bm.commitment_item_id = ci.commitment_item_id
                {where_sql}
                ORDER BY
                    ue.unit_entity NULLS LAST,
                    b.biro_code NULLS LAST,
                    fc.funds_center_code NULLS LAST,
                    ci.commitment_item_code NULLS LAST,
                    bm.budget_id
            """, params)

            rows = cursor.fetchall()

        details = []
        for row in rows:
            details.append({
                "budget_id": row[0],
                "entity": row[1] or "-",
                "scope": row[2] or "-",
                "biro_code": row[3] or "-",
                "biro_name": row[4] or "-",
                "biro": (
                    f"{row[3]} - {row[4]}" if row[3] and row[4]
                    else str(row[3] or row[4] or "-")
                ),
                "funds_center": row[5] or "-",
                "commitment_item": row[6] or "-",
                "commitment_name": row[7] or "-",
                "current": float(row[8] or 0),
                "consumable": float(row[9] or 0),
                "consumed": float(row[10] or 0),
                "available": float(row[11] or 0),
                "utilization": float(row[12]) if row[12] is not None else None
            })

        return {
            "details": details,
            "page": 1,
            "per_page": total_rows,
            "total_rows": total_rows,
            "total_pages": 1
        }
    finally:
        conn.close()


@app.route("/budget-detail-approval", methods=["GET"])
def budget_detail_approval():
    if not session.get("user_id"):
        flash("Silakan login terlebih dahulu.", "danger")
        return redirect(url_for("login"))

    if session.get("role") != "Approval":
        return redirect(url_for("dashboard"))

    try:
        options = get_approval_budget_options()
        if not options["years"]:
            flash("Data budget NRM belum tersedia.", "warning")
            return redirect(url_for("profil_approval"))

        selected_year = request.args.get("year", type=int)
        if selected_year not in options["years"]:
            selected_year = options["years"][0]

        selected_scope = request.args.get("scope", "all")
        if selected_scope not in ("all", "FC_CI", "CI_ONLY"):
            selected_scope = "all"

        # getlist memungkinkan beberapa checkbox dipilih sekaligus.
        selected_entities = request.args.getlist("entity_id")
        selected_biros = request.args.getlist("biro_id")
        selected_fcs = request.args.getlist("funds_center_id")
        selected_cis = request.args.getlist("commitment_item_id")

        keyword = request.args.get("q", "").strip()[:100]
        valid_entities = {str(x["id"]) for x in options["entities"]}
        valid_biros = {str(x["id"]) for x in options["biros"]}
        valid_fcs = {str(x["id"]) for x in options["funds_centers"]}
        valid_cis = {str(x["id"]) for x in options["commitment_items"]}

        # Buang ID yang tidak dikenal agar query hanya memakai opsi sah.
        selected_entities = [x for x in selected_entities if x in valid_entities]
        selected_biros = [x for x in selected_biros if x in valid_biros]
        selected_fcs = [x for x in selected_fcs if x in valid_fcs]
        selected_cis = [x for x in selected_cis if x in valid_cis]

        result = get_approval_budget_detail(
            budget_year=selected_year,
            budget_scope=selected_scope,
            entity_ids=selected_entities,
            biro_ids=selected_biros,
            funds_center_ids=selected_fcs,
            commitment_item_ids=selected_cis,
            keyword=keyword
        )

        return render_template(
            "budget_detail_approval.html",
            username=session.get("username", ""),
            budget_years=options["years"],
            entity_options=options["entities"],
            biro_options=options["biros"],
            funds_center_options=options["funds_centers"],
            commitment_item_options=options["commitment_items"],
            selected_year=selected_year,
            selected_scope=selected_scope,
            selected_entities=selected_entities,
            selected_biros=selected_biros,
            selected_fcs=selected_fcs,
            selected_cis=selected_cis,
            keyword=keyword,
            budget_details=result["details"],
            page=result["page"],
            per_page=result["per_page"],
            total_rows=result["total_rows"],
            total_pages=result["total_pages"]
        )
    except psycopg2.Error:
        app.logger.exception("Gagal memuat Budget Detail Approval")
        flash("Data Budget Detail Approval gagal dimuat.", "danger")
        return redirect(url_for("dashboard"))


# halaman dashboard berdasarkan role
@app.route("/dashboard")
def dashboard():

    # Validasi login
    if not session.get("user_id"):
        flash("Silakan login terlebih dahulu.", "danger")
        return redirect(url_for("login"))

    role = session.get("role")

    # dashboard approval
    if role == "Approval":

        try:
            # Ambil pilihan filter Approval
            options = get_approval_budget_options()

            if not options["years"]:
                flash(
                    "Data budget NRM belum tersedia.",
                    "warning"
                )
                return redirect(url_for("profil_approval"))

            # Filter tahun
            selected_year = request.args.get(
                "year",
                type=int
            )

            if selected_year not in options["years"]:
                selected_year = options["years"][0]

            # Filter budget scope
            selected_scope = request.args.get(
                "scope",
                "all"
            )

            if selected_scope not in (
                "all",
                "FC_CI",
                "CI_ONLY"
            ):
                selected_scope = "all"

            # Filter entity
            selected_entity = request.args.get(
                "entity_id",
                "all"
            )

            # Filter funds center
            selected_fc = request.args.get(
                "funds_center_id",
                "all"
            )

            # Filter commitment item
            selected_ci = request.args.get(
                "commitment_item_id",
                "all"
            )

            # Filter biro
            selected_biro = request.args.get(
                "biro_id",
                "all"
            )

            # Validasi pilihan filter entity
            valid_entities = {
                str(item["id"])
                for item in options["entities"]
            }

            # Validasi pilihan filter funds center
            valid_fcs = {
                str(item["id"])
                for item in options["funds_centers"]
            }

            # Validasi pilihan filter commitment item
            valid_cis = {
                str(item["id"])
                for item in options["commitment_items"]
            }

            valid_biros = {
                str(item["id"])
                for item in options["biros"]
            }

            if (
                selected_entity != "all"
                and selected_entity not in valid_entities
            ):
                selected_entity = "all"

            if (
                selected_fc != "all"
                and selected_fc not in valid_fcs
            ):
                selected_fc = "all"

            if (
                selected_ci != "all"
                and selected_ci not in valid_cis
            ):
                selected_ci = "all"

            if (
                selected_biro != "all"
                and selected_biro not in valid_biros
            ):
                selected_biro = "all"

            # Ambil data dashboard Approval
            dashboard_data = get_approval_budget_data(
                budget_year=selected_year,
                budget_scope=selected_scope,
                entity_id=selected_entity,
                funds_center_id=selected_fc,
                commitment_item_id=selected_ci,
                biro_id=selected_biro
            )

            # Tampilkan dashboard Approval
            return render_template(
                "dashboard_approval.html",

                username=session.get("username"),

                # Data pilihan filter
                budget_years=options["years"],
                entity_options=options["entities"],
                funds_center_options=options["funds_centers"],
                commitment_item_options=options["commitment_items"],
                biro_options=options["biros"],

                # Filter yang sedang digunakan
                selected_year=selected_year,
                selected_scope=selected_scope,
                selected_entity=selected_entity,
                selected_fc=selected_fc,
                selected_ci=selected_ci,
                selected_biro=selected_biro,

                # Data dashboard
                summary=dashboard_data["summary"],
                scope_summary=dashboard_data["scope_summary"],
                visualization_data=dashboard_data["visualization_data"]
            )

        except psycopg2.Error:
            app.logger.exception(
                "Gagal memuat Dashboard Budgeting Approval"
            )

            flash(
                "Dashboard Budgeting Approval gagal dimuat.",
                "danger"
            )

            return redirect(url_for("profil_approval"))

    # validasi role pengusul
    if role != "Pengusul":
        session.clear()
        return redirect(url_for("login"))

    user_id = session["user_id"]

    try:

        # Daftar periode yang tersedia
        budget_years = get_budget_years(user_id)

        if not budget_years:
            flash(
                "Data budget untuk Biro ini belum tersedia.",
                "warning"
            )
            return redirect(url_for("profil"))

        # Filter tahun
        selected_year = request.args.get(
            "year",
            type=int
        )

        if selected_year not in budget_years:
            selected_year = budget_years[0]

        # Daftar entity sesuai kode biro
        entity_options = get_pengusul_entity_options(user_id)

        # Filter entity
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
                flash(
                    "Unit Entity tidak valid.",
                    "danger"
                )
                return redirect(url_for("dashboard"))

        # Ubah entity ID menjadi integer atau None
        entity_filter = (
            None
            if selected_entity_id == "all"
            else int(selected_entity_id)
        )

        # Ringkasan budget
        budget_summary = get_pengusul_budget_summary(
            user_id,
            selected_year,
            entity_filter
        )

        # Mengambil lima commitment item terbesar
        top5_details = get_pengusul_top5_details(
            user_id,
            selected_year,
            entity_filter
        )

        # Tampilkan dashboard Pengusul
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

        app.logger.exception(
            "Gagal memuat dashboard pengusul"
        )

        flash(
            "Dashboard gagal dimuat.",
            "danger"
        )

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
    """
    Mapping menggunakan rentang From-To.
    FUND dan FUNDS CENTER mendukung kode alfanumerik.
    COMMITMENT ITEM menggunakan perbandingan numerik.
    """

    queries = (
        (
            "fund",
            """
            SELECT
                mf.target_fund_id AS id,
                f.fund_code AS code
            FROM public.master_fund mf
            JOIN public.fund f
                ON f.fund_id = mf.target_fund_id
            WHERE
                TRIM(mf.from_profit_center::text)
                    ~ '^[A-Za-z0-9]+$'
                AND TRIM(mf.to_profit_center::text)
                    ~ '^[A-Za-z0-9]+$'
                AND (
                    UPPER(TRIM(%s::text)) COLLATE "C"
                ) BETWEEN (
                    UPPER(TRIM(mf.from_profit_center::text)) COLLATE "C"
                ) AND (
                    UPPER(TRIM(mf.to_profit_center::text)) COLLATE "C"
                )
            LIMIT 2
            """,
            data["profit_center"],
            "alphanumeric",
        ),
        (
            "funds_center",
            """
            SELECT
                mfc.target_funds_center_id AS id,
                fc.funds_center_code AS code
            FROM public.master_fc mfc
            JOIN public.funds_center fc
                ON fc.funds_center_id =
                   mfc.target_funds_center_id
            WHERE
                TRIM(mfc.from_cost_center::text)
                    ~ '^[A-Za-z0-9]+$'
                AND TRIM(mfc.to_cost_center::text)
                    ~ '^[A-Za-z0-9]+$'
                AND (
                    UPPER(TRIM(%s::text)) COLLATE "C"
                ) BETWEEN (
                    UPPER(TRIM(mfc.from_cost_center::text)) COLLATE "C"
                ) AND (
                    UPPER(TRIM(mfc.to_cost_center::text)) COLLATE "C"
                )
            LIMIT 2
            """,
            data["cost_center"],
            "alphanumeric",
        ),
        (
            "commitment_item",
            """
            SELECT
                mci.target_commitment_item_id AS id,
                ci.commitment_item_code AS code,
                ci.commitment_item_name AS name
            FROM public.master_ci mci
            JOIN public.commitment_item ci
                ON ci.commitment_item_id =
                   mci.target_commitment_item_id
            WHERE
                TRIM(mci.from_gl_account::text)
                    ~ '^[0-9]+$'
                AND TRIM(mci.to_gl_account::text)
                    ~ '^[0-9]+$'
                AND %s::numeric BETWEEN
                    TRIM(mci.from_gl_account::text)::numeric
                    AND
                    TRIM(mci.to_gl_account::text)::numeric
            LIMIT 2
            """,
            data["gl_account"],
            "numeric",
        ),
    )

    mapped = {}
    missing = []

    for key, sql, input_value, input_type in queries:
        normalized_input = str(input_value).strip()

        if input_type == "numeric":
            valid_input = (
                normalized_input.isascii()
                and normalized_input.isdigit()
            )
        else:
            valid_input = (
                normalized_input.isascii()
                and normalized_input.isalnum()
            )

        if not valid_input:
            missing.append(key)
            continue

        cursor.execute(sql, (normalized_input,))
        rows = cursor.fetchall()

        if len(rows) > 1:
            raise PengajuanValidationError(
                "Mapping master ambigu: " + key,
                409
            )

        if not rows:
            missing.append(key)
        else:
            mapped[key] = rows[0]

    if missing:
        raise PengajuanValidationError(
            "Mapping tidak ditemukan: " + ", ".join(missing),
            422
        )

    return mapped




def pengajuan_public_mapping(mapped):
    return {
        "mapping_status": "Oke",

        "mapped_fund": {
            "id": mapped["fund"]["id"],
            "code": mapped["fund"]["code"],
        },

        "mapped_funds_center": {
            "id": mapped["funds_center"]["id"],
            "code": mapped["funds_center"]["code"],
        },

        "mapped_commitment_item": {
            "id": mapped["commitment_item"]["id"],
            "code": mapped["commitment_item"]["code"],
            "name": (
                mapped["commitment_item"]["name"]
                or "Nama belum tersedia"
            ),
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
    # ==========================================
    # 1. IDENTIFIKASI BIRO PENGUSUL
    # ==========================================
    biro = pengajuan_get_biro(
        cursor,
        user_id,
        data["entity_id"]
    )

    # ==========================================
    # 2. MAPPING MASTER
    # ==========================================
    mapped = pengajuan_get_mapping(
        cursor,
        data
    )

    # ==========================================
    # 3. PENCARIAN BUDGET
    # ==========================================
    budget = pengajuan_find_budget(
        cursor,
        biro["biro_id"],
        data["entity_id"],
        data["transaction_date"].year,
        mapped
    )

    # Jika sumber budget tidak ditemukan.
    if budget is None:
        return {
            "mapped": mapped,
            "budget": None,
            "shortage": None,
            "budget_status": "Review",
            "message": (
                "Mapping berhasil, tetapi sumber budget "
                "tidak ditemukan. Perlu pemeriksaan Approval."
            ),
        }

    # ==========================================
    # 4. VALIDASI AVAILABLE BUDGET
    # ==========================================
    if budget["available_amount"] is None:
        raise PengajuanValidationError(
            "Available Amount pada sumber budget belum tersedia.",
            422
        )

    available = Decimal(
        str(budget["available_amount"])
    )

    if not available.is_finite() or available < 0:
        raise PengajuanValidationError(
            "Available Budget tidak valid.",
            422
        )

    request_amount = data["request_amount"]

    # ==========================================
    # 5. HITUNG SHORTAGE
    # ==========================================
    shortage = max(
        Decimal("0"),
        request_amount - available
    )

    # ==========================================
    # 6. TENTUKAN STATUS BUDGET
    # ==========================================
    budget_status = (
        "Review"
        if shortage > 0
        else "Budget Cukup"
    )

    message = (
        "Budget kurang; pengajuan memerlukan review Approval."
        if shortage > 0
        else "Budget mencukupi; pengajuan dapat direview Approval."
    )

    return {
        "mapped": mapped,
        "budget": budget,
        "shortage": shortage,
        "budget_status": budget_status,
        "message": message,
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
    # ==========================================
    # 1. VALIDASI AKSES
    # ==========================================
    guard = pengajuan_api_guard()
    if guard is not None:
        return guard

    # Upload lampiran belum tersedia.
    if request.files:
        return jsonify({
            "success": False,
            "error": "Upload lampiran belum tersedia."
        }), 422

    payload = request.get_json(silent=True) or {}

    if payload.get("lampiran") or payload.get("attachment"):
        return jsonify({
            "success": False,
            "error": "Upload lampiran belum tersedia."
        }), 422

    conn = None

    try:
        # ==========================================
        # 2. VALIDASI INPUT PENGAJUAN
        # ==========================================
        data = pengajuan_parse_input(
            payload,
            require_details=True
        )

        conn = get_db_connection()

        # Seluruh proses penyimpanan berada dalam
        # satu transaksi database.
        with conn:
            with conn.cursor(
                cursor_factory=RealDictCursor
            ) as cursor:

                # ==================================
                # 3. MAPPING DAN PEMERIKSAAN BUDGET
                # ==================================
                result = pengajuan_check(
                    cursor,
                    session["user_id"],
                    data
                )

                mapped = result["mapped"]
                budget = result["budget"]

                # Sumber budget wajib ditemukan.
                if budget is None:
                    raise PengajuanValidationError(
                        "Sumber budget tidak ditemukan. "
                        "Pengajuan belum dapat dikirim.",
                        422
                    )

                # ==================================
                # 4. VALIDASI NILAI BUDGET
                # ==================================
                current = budget["current_budget"]
                consumable = budget["consumable_budget"]
                available = budget["available_amount"]

                if (
                    current is None
                    or consumable is None
                    or available is None
                ):
                    raise PengajuanValidationError(
                        "Data Current, Consumable, atau "
                        "Available Budget belum lengkap.",
                        422
                    )

                current = Decimal(str(current))
                consumable = Decimal(str(consumable))
                available = Decimal(str(available))

                if current < 0 or consumable < 0 or available < 0:
                    raise PengajuanValidationError(
                        "Nilai budget tidak boleh negatif.",
                        422
                    )

                if consumable > current:
                    raise PengajuanValidationError(
                        "Consumable Budget melebihi Current Budget.",
                        422
                    )

                # Approval Hold merupakan bagian Current
                # Budget yang belum menjadi Consumable.
                approval_hold = current - consumable

                # ==================================
                # 5. VALIDASI STATUS
                # ==================================
                mapping_status = "Oke"

                budget_status = result["budget_status"]

                allowed_budget_status = {
                    "Budget Cukup",
                    "Review"
                }

                if budget_status not in allowed_budget_status:
                    raise PengajuanValidationError(
                        "Status budget tidak sesuai dengan "
                        "standar database.",
                        422
                    )

                request_status = "Pending"

                # ==================================
                # 6. SIMPAN PENGAJUAN
                # ==================================
                cursor.execute("""
                    INSERT INTO public.budget_request (
                        user_id,
                        entity_id,
                        request_date,
                        transaction_date,
                        pic,

                        input_profit_center,
                        input_cost_center,
                        input_gl_account,

                        request_amount,
                        request_description,

                        mapped_fund_id,
                        mapped_funds_center_id,
                        mapped_commitment_item_id,

                        budget_id,
                        budget_scope,

                        available_amount_snapshot,
                        shortage_amount,
                        approval_hold_amount_snapshot,

                        mapping_status,
                        budget_status,
                        request_status
                    )
                    VALUES (
                        %s, %s, NOW(), %s, %s,
                        %s, %s, %s,
                        %s, %s,
                        %s, %s, %s,
                        %s, %s,
                        %s, %s, %s,
                        %s, %s, %s
                    )
                    RETURNING request_id, request_date,
                              transaction_date
                """, (
                    session["user_id"],
                    data["entity_id"],
                    data["transaction_date"],
                    data["pic"],

                    data["profit_center"],
                    data["cost_center"],
                    data["gl_account"],

                    data["request_amount"],
                    data["description"],

                    mapped["fund"]["id"],
                    mapped["funds_center"]["id"],
                    mapped["commitment_item"]["id"],

                    budget["budget_id"],
                    budget["budget_scope"],

                    available,
                    result["shortage"],
                    approval_hold,

                    mapping_status,
                    budget_status,
                    request_status
                ))

                saved = cursor.fetchone()

        # ==========================================
        # 7. RESPONS API BERHASIL
        # ==========================================
        return jsonify({
            "success": True,

            "request_id": saved["request_id"],

            "request_date": (
                saved["request_date"].isoformat()
                if saved["request_date"] else None
            ),

            "transaction_date": (
                saved["transaction_date"].isoformat()
                if saved["transaction_date"] else None
            ),

            "mapping_status": mapping_status,
            "budget_status": budget_status,
            "request_status": request_status,

            "budget_scope": budget["budget_scope"],

            "request_amount": str(data["request_amount"]),
            "available_amount_snapshot": str(available),
            "shortage_amount": (
                str(result["shortage"])
                if result["shortage"] is not None
                else None
            ),

            "message": (
                "Pengajuan berhasil dikirim "
                "dan menunggu keputusan Approval."
            )
        }), 201

    # ==============================================
    # 8. PENANGANAN ERROR
    # ==============================================
    except PengajuanValidationError as exc:

        if conn is not None:
            conn.rollback()

        return jsonify({
            "success": False,
            "error": str(exc)
        }), exc.status_code

    except psycopg2.Error:

        if conn is not None:
            conn.rollback()

        app.logger.exception(
            "Gagal menyimpan pengajuan budget"
        )

        return jsonify({
            "success": False,
            "error": "Pengajuan gagal disimpan."
        }), 500

    except Exception:

        if conn is not None:
            conn.rollback()

        app.logger.exception(
            "Terjadi kesalahan pada proses pengajuan"
        )

        return jsonify({
            "success": False,
            "error": "Terjadi kesalahan saat memproses pengajuan."
        }), 500

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

# halaman profil approval
def get_approval_csrf_token():
    if "approval_password_csrf" not in session:
        session["approval_password_csrf"] = secrets.token_urlsafe(32)

    return session["approval_password_csrf"]


@app.route("/profil-approval", methods=["GET"])
def profil_approval():

    # 1. Pastikan pengguna sudah login
    if not session.get("user_id"):
        flash("Silakan login terlebih dahulu.", "danger")
        return redirect(url_for("login"))

    # 2. Halaman ini hanya untuk Approval
    if session.get("role") != "Approval":
        return redirect(url_for("dashboard"))

    conn = None

    try:
        # 3. Ambil data akun dari database
        conn = get_db_connection()

        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT username, role
                FROM public.users
                WHERE user_id = %s
                  AND role = 'Approval'
                LIMIT 1
                """,
                (session["user_id"],)
            )

            result = cursor.fetchone()

        # 4. Validasi akun
        if result is None:
            session.clear()
            flash(
                "Akun Approval tidak ditemukan.",
                "danger"
            )
            return redirect(url_for("login"))

        # 5. Data yang ditampilkan pada halaman Profil
        user = {
            "username": result[0],
            "role": result[1]
        }

        # 6. Render halaman Profil Approval
        return render_template(
            "profil_approval.html",
            user=user,
            approval_csrf_token=get_approval_csrf_token()
        )

    except psycopg2.Error:
        app.logger.exception(
            "Gagal memuat Profil Approval"
        )

        flash(
            "Data Profil Approval gagal dimuat.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    finally:
        if conn is not None:
            conn.close()


# ubah password approval
@app.route(
    "/ubah-password-approval",
    methods=["POST"]
)
def ubah_password_approval():

    # 1. Validasi login
    if not session.get("user_id"):
        flash("Silakan login terlebih dahulu.", "danger")
        return redirect(url_for("login"))

    # 2. Validasi role
    if session.get("role") != "Approval":
        return redirect(url_for("dashboard"))

    # 3. Validasi CSRF
    expected_token = session.get(
        "approval_password_csrf",
        ""
    )

    submitted_token = request.form.get(
        "approval_csrf_token",
        ""
    )

    if (
        not expected_token
        or not submitted_token
        or not hmac.compare_digest(
            expected_token,
            submitted_token
        )
    ):
        flash(
            "Token keamanan tidak valid. Silakan coba lagi.",
            "danger"
        )
        return redirect(url_for("profil_approval"))

    # 4. Ambil input password
    password_lama = request.form.get(
        "password_lama",
        ""
    )

    password_baru = request.form.get(
        "password_baru",
        ""
    )

    konfirmasi = request.form.get(
        "konfirmasi_password",
        ""
    )

    # 5. Validasi kelengkapan
    if not password_lama or not password_baru or not konfirmasi:
        flash(
            "Semua kolom password wajib diisi.",
            "danger"
        )
        return redirect(url_for("profil_approval"))

    # 6. Validasi panjang password
    if len(password_baru) < 8:
        flash(
            "Password baru minimal 8 karakter.",
            "danger"
        )
        return redirect(url_for("profil_approval"))

    # 7. Validasi konfirmasi
    if password_baru != konfirmasi:
        flash(
            "Konfirmasi password baru tidak sesuai.",
            "danger"
        )
        return redirect(url_for("profil_approval"))

    # 8. Password baru harus berbeda
    if password_baru == password_lama:
        flash(
            "Password baru harus berbeda dari password lama.",
            "danger"
        )
        return redirect(url_for("profil_approval"))

    conn = None

    try:
        conn = get_db_connection()

        with conn:
            with conn.cursor() as cursor:

                # 9. Ambil password akun yang sedang login
                # FOR UPDATE mencegah perubahan bersamaan
                cursor.execute(
                    """
                    SELECT password
                    FROM public.users
                    WHERE user_id = %s
                      AND role = 'Approval'
                    FOR UPDATE
                    """,
                    (session["user_id"],)
                )

                result = cursor.fetchone()

                if result is None:
                    flash(
                        "Akun Approval tidak ditemukan.",
                        "danger"
                    )
                    return redirect(
                        url_for("profil_approval")
                    )

                # 10. Periksa password lama
                if not verify_password(
                    password_lama,
                    result[0]
                ):
                    flash(
                        "Password lama tidak sesuai.",
                        "danger"
                    )
                    return redirect(
                        url_for("profil_approval")
                    )

                # 11. Buat hash password baru
                password_hash = generate_password_hash(
                    password_baru
                )

                # 12. Simpan password baru
                cursor.execute(
                    """
                    UPDATE public.users
                    SET password = %s
                    WHERE user_id = %s
                      AND role = 'Approval'
                    """,
                    (
                        password_hash,
                        session["user_id"]
                    )
                )

                if cursor.rowcount != 1:
                    raise RuntimeError(
                        "Gagal memperbarui akun Approval."
                    )

        # 13. Buat ulang token setelah berhasil
        session.pop("approval_password_csrf", None)

        flash(
            "Password berhasil diperbarui.",
            "success"
        )

        return redirect(
            url_for("profil_approval")
        )

    except (psycopg2.Error, RuntimeError):
        app.logger.exception(
            "Gagal mengubah password Approval"
        )

        flash(
            "Password gagal diperbarui.",
            "danger"
        )

        return redirect(
            url_for("profil_approval")
        )

    finally:
        if conn is not None:
            conn.close()



# ============================================================
# MANAJEMEN APPROVAL - REQUEST QUEUE (READ ONLY PHASE)
# Menggunakan struktur aktual schema_silog.sql.
# Keputusan dan mutasi budget akan ditambahkan setelah uji queue.
# ============================================================

def approval_page_guard():
    if not session.get("user_id"):
        flash("Silakan login terlebih dahulu.", "danger")
        return redirect(url_for("login"))
    if session.get("role") != "Approval":
        flash("Akses hanya untuk pengguna Approval.", "danger")
        return redirect(url_for("dashboard"))
    return None


def approval_api_guard():
    if not session.get("user_id"):
        return jsonify({"error": "Silakan login terlebih dahulu."}), 401
    if session.get("role") != "Approval":
        return jsonify({"error": "Akses hanya untuk pengguna Approval."}), 403
    return None


@app.route("/manajemen-approval", methods=["GET"])
def manajemen_approval():
    guard = approval_page_guard()
    if guard is not None:
        return guard
    return render_template(
        "manajemen_approval.html",
        username=session.get("username", ""),
        approval_csrf_token=get_approval_csrf_token()
    )


@app.route("/api/approval/summary", methods=["GET"])
def api_approval_summary():
    guard = approval_api_guard()
    if guard is not None:
        return guard

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
                SELECT
                    COUNT(*)::integer AS total_requests,
                    COUNT(*) FILTER (WHERE request_status = 'Pending')::integer AS pending,
                    COUNT(*) FILTER (WHERE request_status = 'Approved')::integer AS approved,
                    COUNT(*) FILTER (WHERE request_status = 'Rejected')::integer AS rejected,
                    COALESCE(SUM(request_amount) FILTER (
                        WHERE request_status = 'Pending'
                    ), 0) AS pending_amount
                FROM public.budget_request
            """)
            row = cursor.fetchone()
        return jsonify({
            key: (str(value) if isinstance(value, Decimal) else value)
            for key, value in row.items()
        })
    except psycopg2.Error:
        app.logger.exception("Gagal memuat ringkasan Manajemen Approval")
        return jsonify({"error": "Ringkasan pengajuan gagal dimuat."}), 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/api/approval/requests", methods=["GET"])
def api_approval_requests():
    guard = approval_api_guard()
    if guard is not None:
        return guard

    status = request.args.get("status", "ALL").strip()
    entity_id = request.args.get("entity_id", "").strip()
    biro_id = request.args.get("biro_id", "").strip()
    keyword = request.args.get("q", "").strip()
    page = max(1, request.args.get("page", 1, type=int))
    per_page = request.args.get("per_page", 10, type=int)
    per_page = min(max(per_page, 10), 50)

    allowed_status = {"ALL", "Pending", "Approved", "Rejected"}
    if status not in allowed_status:
        return jsonify({"error": "Filter status tidak valid."}), 400
    if entity_id and not entity_id.isdigit():
        return jsonify({"error": "Filter Unit Entity tidak valid."}), 400
    if biro_id and not biro_id.isdigit():
        return jsonify({"error": "Filter Biro tidak valid."}), 400
    if len(keyword) > 150:
        return jsonify({"error": "Kata pencarian terlalu panjang."}), 400

    where = ["1=1"]
    params = []
    if status != "ALL":
        where.append("br.request_status = %s")
        params.append(status)
    if entity_id:
        where.append("br.entity_id = %s")
        params.append(int(entity_id))
    if biro_id:
        where.append("u.biro_id = %s")
        params.append(int(biro_id))
    if keyword:
        where.append("""(
            CAST(br.request_id AS TEXT) ILIKE %s
            OR COALESCE(br.pic, '') ILIKE %s
            OR COALESCE(br.request_description, '') ILIKE %s
            OR COALESCE(u.username, '') ILIKE %s
            OR COALESCE(ci.commitment_item_code, '') ILIKE %s
            OR COALESCE(ci.commitment_item_name, '') ILIKE %s
        )""")
        params.extend([f"%{keyword}%"] * 6)

    where_sql = " AND ".join(where)
    offset = (page - 1) * per_page
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(f"""
                SELECT COUNT(*)::integer AS total
                FROM public.budget_request br
                JOIN public.users u ON u.user_id = br.user_id
                LEFT JOIN public.commitment_item ci
                    ON ci.commitment_item_id = br.mapped_commitment_item_id
                WHERE {where_sql}
            """, params)
            total = cursor.fetchone()["total"]

            cursor.execute(f"""
                SELECT
                    br.request_id,
                    br.entity_id,
                    u.biro_id,
                    br.request_date,
                    br.pic,
                    br.request_amount,
                    br.request_description,
                    br.available_amount_snapshot,
                    br.shortage_amount,
                    br.approval_hold_amount_snapshot,
                    br.mapping_status,
                    br.budget_status,
                    br.request_status,
                    br.budget_scope,
                    latest_decision.decision AS approval_decision,
                    u.username AS requester_username,
                    ue.unit_entity,
                    b.biro_name,
                    f.fund_code,
                    fc.funds_center_code,
                    ci.commitment_item_code,
                    ci.commitment_item_name
                FROM public.budget_request br
                JOIN public.users u ON u.user_id = br.user_id
                LEFT JOIN public.unit_entity ue ON ue.entity_id = br.entity_id
                LEFT JOIN public.biro b
                    ON b.biro_id = u.biro_id
                   AND b.entity_id = br.entity_id
                LEFT JOIN public.fund f ON f.fund_id = br.mapped_fund_id
                LEFT JOIN public.funds_center fc
                    ON fc.funds_center_id = br.mapped_funds_center_id
                LEFT JOIN public.commitment_item ci
                    ON ci.commitment_item_id = br.mapped_commitment_item_id
                LEFT JOIN LATERAL (
                    SELECT ad.decision
                    FROM public.approval_decision ad
                    WHERE ad.request_id = br.request_id
                    ORDER BY ad.decision_date DESC, ad.approval_id DESC
                    LIMIT 1
                ) latest_decision ON TRUE
                WHERE {where_sql}
                ORDER BY
                    CASE br.request_status WHEN 'Pending' THEN 0
                         WHEN 'Approved' THEN 1 ELSE 2 END,
                    br.request_date ASC,
                    br.request_id ASC
                LIMIT %s OFFSET %s
            """, params + [per_page, offset])
            rows = cursor.fetchall()

        items = []
        for row in rows:
            item = {}
            for key, value in row.items():
                if isinstance(value, Decimal):
                    item[key] = str(value)
                elif hasattr(value, "isoformat"):
                    item[key] = value.isoformat()
                else:
                    item[key] = value
            items.append(item)

        return jsonify({
            "items": items,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "pages": (total + per_page - 1) // per_page
            }
        })
    except psycopg2.Error:
        app.logger.exception("Gagal memuat daftar pengajuan Approval")
        return jsonify({"error": "Daftar pengajuan gagal dimuat."}), 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/api/approval/requests/<int:request_id>", methods=["GET"])
def api_approval_request_detail(request_id):
    guard = approval_api_guard()
    if guard is not None:
        return guard

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
                SELECT
                    br.*,
                    u.username AS requester_username,
                    ue.unit_entity,
                    b.biro_name,
                    f.fund_code,
                    fc.funds_center_code,
                    ci.commitment_item_code,
                    ci.commitment_item_name,
                    bm.current_budget,
                    bm.consumable_budget,
                    bm.consumed_budget,
                    bm.available_amount AS current_available_amount,
                    bm.budget_scope AS current_budget_scope
                FROM public.budget_request br
                JOIN public.users u ON u.user_id = br.user_id
                LEFT JOIN public.unit_entity ue ON ue.entity_id = br.entity_id
                LEFT JOIN public.biro b
                    ON b.biro_id = u.biro_id
                   AND b.entity_id = br.entity_id
                LEFT JOIN public.fund f ON f.fund_id = br.mapped_fund_id
                LEFT JOIN public.funds_center fc
                    ON fc.funds_center_id = br.mapped_funds_center_id
                LEFT JOIN public.commitment_item ci
                    ON ci.commitment_item_id = br.mapped_commitment_item_id
                LEFT JOIN public.budget_master bm ON bm.budget_id = br.budget_id
                WHERE br.request_id = %s
                LIMIT 1
            """, (request_id,))
            row = cursor.fetchone()
            if row is None:
                return jsonify({"error": "Pengajuan tidak ditemukan."}), 404

            cursor.execute("""
                SELECT
                    ad.approval_id,
                    ad.decision,
                    ad.instruction,
                    ad.approved_amount,
                    ad.decision_date,
                    u.username AS approval_username
                FROM public.approval_decision ad
                JOIN public.users u ON u.user_id = ad.approval_user_id
                WHERE ad.request_id = %s
                ORDER BY ad.decision_date DESC, ad.approval_id DESC
            """, (request_id,))
            decisions = cursor.fetchall()

            cursor.execute("""
                SELECT
                    ba.allocation_id,
                    ba.allocation_type,
                    ba.amount,
                    ba.instruction,
                    ba.source_budget_id,
                    ba.target_budget_id,
                    ba.approved_by
                FROM public.budget_allocation ba
                WHERE ba.request_id = %s
                ORDER BY ba.allocation_id
            """, (request_id,))
            allocations = cursor.fetchall()

        def serialize(row_data):
            result = {}
            for key, value in row_data.items():
                if isinstance(value, Decimal):
                    result[key] = str(value)
                elif hasattr(value, "isoformat"):
                    result[key] = value.isoformat()
                else:
                    result[key] = value
            return result

        return jsonify({
            "request": serialize(row),
            "decisions": [serialize(x) for x in decisions],
            "allocations": [serialize(x) for x in allocations]
        })
    except psycopg2.Error:
        app.logger.exception("Gagal memuat detail pengajuan Approval")
        return jsonify({"error": "Detail pengajuan gagal dimuat."}), 500
    finally:
        if conn is not None:
            conn.close()



# ============================================================
# MANAJEMEN APPROVAL - OPEN BUDGET & REALLOCATION
# Seluruh perubahan budget, keputusan, alokasi, dan history
# dijalankan dalam satu transaksi database.
# ============================================================

def approval_mutation_guard():
    guard = approval_api_guard()
    if guard is not None:
        return guard
    supplied = request.headers.get("X-CSRFToken", "")
    expected = session.get("approval_password_csrf", "")
    if not supplied or not expected or not hmac.compare_digest(supplied, expected):
        return jsonify({"error": "Token keamanan tidak valid. Muat ulang halaman lalu coba kembali."}), 403
    return None


def _approval_decimal(value, label="Nominal"):
    try:
        amount = Decimal(str(value).replace(",", "").strip())
    except (InvalidOperation, TypeError, ValueError, AttributeError):
        raise ValueError(f"{label} tidak valid.")
    if not amount.is_finite() or amount <= 0:
        raise ValueError(f"{label} harus lebih besar dari Rp0.")
    if amount.quantize(Decimal("0.01")) != amount:
        raise ValueError(f"{label} maksimal memiliki dua angka desimal.")
    return amount


def _approval_record_decision(cursor, request_id, decision, amount, instruction):
    cursor.execute("""
        INSERT INTO public.approval_decision
            (request_id, approval_user_id, decision, instruction, approved_amount)
        VALUES (%s, %s, %s, %s, %s)
    """, (request_id, session["user_id"], decision, instruction, amount))


def _approval_record_history(cursor, budget_id, request_id, action,
                             field_name, previous_value, updated_value, amount):
    cursor.execute("""
        INSERT INTO public.budget_history
            (budget_id, request_id, action, field_name,
             previous_value, updated_value, amount, created_by)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """, (budget_id, request_id, action, field_name,
          previous_value, updated_value, amount, session["user_id"]))


@app.route("/api/approval/requests/<int:request_id>/reallocation-sources", methods=["GET"])
def api_approval_reallocation_sources(request_id):
    guard = approval_api_guard()
    if guard is not None:
        return guard
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Ambil identitas budget target sebagai dasar pencarian kandidat.
            cursor.execute("""
                SELECT
                    br.request_id,
                    br.request_status,
                    br.budget_id,
                    bm.entity_id,
                    bm.biro_id,
                    bm.budget_year,
                    UPPER(TRIM(bm.budget_scope)) AS budget_scope,
                    bm.funds_center_id,
                    bm.commitment_item_id
                FROM public.budget_request br
                JOIN public.budget_master bm ON bm.budget_id = br.budget_id
                WHERE br.request_id = %s
                LIMIT 1
            """, (request_id,))
            target = cursor.fetchone()
            if not target:
                return jsonify({"error": "Pengajuan atau budget tujuan tidak ditemukan."}), 404
            if target["request_status"] != "Pending":
                return jsonify({"error": "Hanya pengajuan Pending yang dapat diproses."}), 409
            if not target["budget_id"]:
                return jsonify({"error": "Pengajuan tidak memiliki sumber budget tujuan."}), 409

            scope = target["budget_scope"]
            if scope == "CI_ONLY":
                # CI_ONLY: hanya Commitment Item yang menjadi kunci.
                scope_condition = "AND bm.commitment_item_id = %s"
                scope_params = (target["commitment_item_id"],)
            elif scope == "FC_CI":
                # FC_CI: Funds Center dan Commitment Item wajib sama.
                scope_condition = "AND bm.funds_center_id = %s AND bm.commitment_item_id = %s"
                scope_params = (target["funds_center_id"], target["commitment_item_id"])
            else:
                return jsonify({"error": "Budget Scope target tidak dikenali."}), 409

            cursor.execute(f"""
                SELECT
                    bm.budget_id,
                    bm.entity_id,
                    ue.unit_entity,
                    bm.biro_id,
                    f.fund_code,
                    b.biro_code,
                    b.biro_name,
                    UPPER(TRIM(bm.budget_scope)) AS budget_scope,
                    bm.funds_center_id,
                    fc.funds_center_code,
                    bm.commitment_item_id,
                    ci.commitment_item_code,
                    ci.commitment_item_name,
                    bm.current_budget,
                    bm.consumable_budget,
                    bm.consumed_budget,
                    bm.available_amount
                FROM public.budget_master bm
                LEFT JOIN public.unit_entity ue ON ue.entity_id = bm.entity_id
                LEFT JOIN LATERAL (
                    SELECT
                        br_source.input_profit_center,
                        br_source.mapped_fund_id
                    FROM public.budget_request br_source
                    WHERE br_source.budget_id = bm.budget_id
                    ORDER BY br_source.request_date DESC, br_source.request_id DESC
                    LIMIT 1
                ) source_request ON TRUE
                LEFT JOIN LATERAL (
                    SELECT MIN(mf.target_fund_id) AS target_fund_id
                    FROM public.master_fund mf
                    WHERE TRIM(mf.from_profit_center::text) ~ '^[A-Za-z0-9]+$'
                      AND TRIM(mf.to_profit_center::text) ~ '^[A-Za-z0-9]+$'
                      AND (
                          UPPER(TRIM(source_request.input_profit_center::text)) COLLATE "C"
                      ) BETWEEN (
                          UPPER(TRIM(mf.from_profit_center::text)) COLLATE "C"
                      ) AND (
                          UPPER(TRIM(mf.to_profit_center::text)) COLLATE "C"
                      )
                    HAVING COUNT(*) = 1
                ) source_fund_map ON TRUE
                LEFT JOIN public.fund f
                    ON f.fund_id = COALESCE(
                        source_fund_map.target_fund_id,
                        source_request.mapped_fund_id
                    )
                LEFT JOIN public.biro b
                    ON b.biro_id = bm.biro_id AND b.entity_id = bm.entity_id
                LEFT JOIN public.funds_center fc
                    ON fc.funds_center_id = bm.funds_center_id
                LEFT JOIN public.commitment_item ci
                    ON ci.commitment_item_id = bm.commitment_item_id
                WHERE bm.budget_year IS NOT DISTINCT FROM %s
                  AND UPPER(TRIM(bm.budget_scope)) = %s
                  AND bm.budget_id <> %s
                  AND NOT (
                      bm.entity_id IS NOT DISTINCT FROM %s
                      AND bm.biro_id IS NOT DISTINCT FROM %s
                  )
                  AND bm.available_amount > 0
                  {scope_condition}
                ORDER BY bm.available_amount DESC, bm.budget_id
            """, (target["budget_year"], scope, target["budget_id"],
                  target["entity_id"], target["biro_id"]) + scope_params)
            rows = cursor.fetchall()
        items = []
        for row in rows:
            items.append({k: (str(v) if isinstance(v, Decimal) else v)
                          for k, v in row.items()})
        return jsonify({"items": items})
    except psycopg2.Error:
        app.logger.exception("Gagal memuat sumber realokasi")
        return jsonify({"error": "Sumber realokasi gagal dimuat."}), 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/api/approval/requests/<int:request_id>/approve", methods=["POST"])
def api_approval_direct_approve(request_id):
    """Approve pengajuan yang dapat dipenuhi oleh available budget saat ini."""
    guard = approval_mutation_guard()
    if guard is not None:
        return guard

    payload = request.get_json(silent=True) or {}
    instruction = str(payload.get("instruction", "")).strip()
    if len(instruction) > 2000:
        return jsonify({"error": "Instruksi maksimal 2.000 karakter."}), 400

    conn = None
    try:
        conn = get_db_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT request_id, request_status, request_amount, budget_id
                    FROM public.budget_request
                    WHERE request_id = %s
                    FOR UPDATE
                """, (request_id,))
                req = cursor.fetchone()
                if not req:
                    return jsonify({"error": "Pengajuan tidak ditemukan."}), 404
                if req["request_status"] != "Pending":
                    return jsonify({"error": "Hanya pengajuan Pending yang dapat disetujui."}), 409
                if not req["budget_id"]:
                    return jsonify({"error": "Sumber budget pengajuan tidak ditemukan."}), 409

                cursor.execute("""
                    SELECT budget_id, available_amount
                    FROM public.budget_master
                    WHERE budget_id = %s
                    FOR UPDATE
                """, (req["budget_id"],))
                budget = cursor.fetchone()
                if not budget:
                    return jsonify({"error": "Data budget pengajuan tidak ditemukan."}), 409

                request_amount = Decimal(str(req["request_amount"]))
                available_amount = Decimal(str(budget["available_amount"]))
                if available_amount < request_amount:
                    shortage = request_amount - available_amount
                    return jsonify({
                        "error": (
                            "Available Budget belum mencukupi. "
                            f"Masih terdapat shortage {shortage:.2f}. "
                            "Gunakan Open Budget atau Reallocation Budget."
                        )
                    }), 409

                cursor.execute("""
                    UPDATE public.budget_request
                    SET request_status = 'Approved', budget_status = 'Budget Cukup'
                    WHERE request_id = %s
                """, (request_id,))
                _approval_record_decision(
                    cursor, request_id, "Approve", request_amount, instruction
                )

        return jsonify({
            "message": "Pengajuan berhasil disetujui tanpa Open Budget.",
            "request_status": "Approved",
            "budget_status": "Budget Cukup",
            "approval_decision": "Approve",
            "approved_amount": str(request_amount)
        })
    except psycopg2.Error:
        app.logger.exception("Gagal menyetujui pengajuan tanpa Open Budget")
        return jsonify({"error": "Approve gagal diproses. Tidak ada perubahan yang disimpan."}), 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/api/approval/requests/<int:request_id>/open-budget", methods=["POST"])
def api_approval_open_budget(request_id):
    guard = approval_mutation_guard()
    if guard is not None:
        return guard
    payload = request.get_json(silent=True) or {}
    try:
        amount = _approval_decimal(payload.get("amount"), "Nominal Open Budget")
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    instruction = str(payload.get("instruction", "")).strip()
    if len(instruction) > 2000:
        return jsonify({"error": "Instruksi maksimal 2.000 karakter."}), 400

    conn = None
    try:
        conn = get_db_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT br.request_id, br.request_status, br.request_amount,
                           br.budget_id, br.budget_scope
                    FROM public.budget_request br
                    WHERE br.request_id = %s
                    FOR UPDATE
                """, (request_id,))
                req = cursor.fetchone()
                if not req:
                    return jsonify({"error": "Pengajuan tidak ditemukan."}), 404
                if req["request_status"] != "Pending":
                    return jsonify({"error": "Pengajuan ini bukan berstatus Pending."}), 409
                if not req["budget_id"]:
                    return jsonify({"error": "Sumber budget pengajuan tidak ditemukan."}), 409

                cursor.execute("""
                    SELECT budget_id, current_budget, consumable_budget,
                           consumed_budget, available_amount, budget_scope
                    FROM public.budget_master
                    WHERE budget_id = %s
                    FOR UPDATE
                """, (req["budget_id"],))
                budget = cursor.fetchone()
                if not budget:
                    return jsonify({"error": "Data budget tujuan tidak ditemukan."}), 409

                hold = Decimal(str(budget["current_budget"])) - Decimal(str(budget["consumable_budget"]))
                live_shortage = max(Decimal("0"), Decimal(str(req["request_amount"])) - Decimal(str(budget["available_amount"])))
                if live_shortage <= 0:
                    return jsonify({"error": "Available Budget saat ini sudah mencukupi. Open Budget tidak diperlukan."}), 409
                if hold < live_shortage:
                    return jsonify({"error": "Approval Hold tidak mencukupi untuk menutup seluruh shortage. Gunakan Open Budget with Reallocation."}), 409
                if hold < amount:
                    return jsonify({"error": f"Nominal melebihi Approval Hold. Maksimal dapat dibuka {hold:.2f}."}), 409
                if amount > live_shortage:
                    return jsonify({"error": f"Nominal melebihi shortage saat ini. Maksimal yang diperlukan {live_shortage:.2f}."}), 409

                old_consumable = Decimal(str(budget["consumable_budget"]))
                old_available = Decimal(str(budget["available_amount"]))
                new_consumable = old_consumable + amount
                new_available = old_available + amount
                cursor.execute("""
                    UPDATE public.budget_master
                    SET consumable_budget = %s, available_amount = %s
                    WHERE budget_id = %s
                """, (new_consumable, new_available, req["budget_id"]))

                remaining_shortage = max(Decimal("0"), Decimal(str(req["request_amount"])) - new_available)
                fully_covered = remaining_shortage == 0
                cursor.execute("""
                    UPDATE public.budget_request
                    SET request_status = %s, budget_status = %s
                    WHERE request_id = %s
                """, ("Approved" if fully_covered else "Pending",
                      "Budget Cukup" if fully_covered else "Open", request_id))

                _approval_record_decision(cursor, request_id, "Open Budget", amount, instruction)
                cursor.execute("""
                    INSERT INTO public.budget_allocation
                        (request_id, source_budget_id, target_budget_id,
                         allocation_type, amount, instruction, approved_by)
                    VALUES (%s, NULL, %s, 'Open Budget', %s, %s, %s)
                """, (request_id, req["budget_id"], amount, instruction, session["user_id"]))
                _approval_record_history(cursor, req["budget_id"], request_id,
                    "Open Budget", "consumable_budget", old_consumable, new_consumable, amount)
                _approval_record_history(cursor, req["budget_id"], request_id,
                    "Open Budget", "available_amount", old_available, new_available, amount)

        return jsonify({
            "message": "Open Budget berhasil diproses.",
            "request_status": "Approved" if fully_covered else "Pending",
            "budget_status": "Budget Cukup" if fully_covered else "Open",
            "opened_amount": str(amount),
            "remaining_shortage": str(remaining_shortage)
        })
    except psycopg2.Error:
        app.logger.exception("Gagal memproses Open Budget")
        return jsonify({"error": "Open Budget gagal diproses. Tidak ada perubahan yang disimpan."}), 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/api/approval/requests/<int:request_id>/reallocate", methods=["POST"])
def api_approval_reallocate(request_id):
    guard = approval_mutation_guard()
    if guard is not None:
        return guard
    payload = request.get_json(silent=True) or {}
    source_id = payload.get("source_budget_id")
    try:
        if isinstance(source_id, bool) or not str(source_id).isdigit():
            raise ValueError("Sumber budget realokasi wajib dipilih.")
        source_id = int(source_id)
        amount = _approval_decimal(payload.get("amount"), "Nominal realokasi")
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    instruction = str(payload.get("instruction", "")).strip()
    if len(instruction) > 2000:
        return jsonify({"error": "Instruksi maksimal 2.000 karakter."}), 400

    conn = None
    try:
        conn = get_db_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT br.request_id, br.request_status, br.request_amount,
                           br.budget_id, br.entity_id, u.biro_id
                    FROM public.budget_request br
                    JOIN public.users u ON u.user_id = br.user_id
                    WHERE br.request_id = %s
                    FOR UPDATE OF br
                """, (request_id,))
                req = cursor.fetchone()
                if not req:
                    return jsonify({"error": "Pengajuan tidak ditemukan."}), 404
                if req["request_status"] != "Pending":
                    return jsonify({"error": "Pengajuan ini bukan berstatus Pending."}), 409
                if not req["budget_id"]:
                    return jsonify({"error": "Sumber budget tujuan tidak ditemukan."}), 409
                if source_id == req["budget_id"]:
                    return jsonify({"error": "Sumber dan target budget tidak boleh sama."}), 400

                # Lock kedua baris secara konsisten untuk mencegah saldo berubah bersamaan.
                ids = sorted([source_id, req["budget_id"]])
                cursor.execute("""
                    SELECT budget_id, entity_id, biro_id, budget_year, budget_scope,
                           funds_center_id, commitment_item_id,
                           current_budget, consumable_budget, consumed_budget, available_amount
                    FROM public.budget_master
                    WHERE budget_id = ANY(%s)
                    ORDER BY budget_id
                    FOR UPDATE
                """, (ids,))
                locked = {r["budget_id"]: r for r in cursor.fetchall()}
                if len(locked) != 2:
                    return jsonify({"error": "Sumber atau target budget tidak ditemukan."}), 404
                source, target = locked[source_id], locked[req["budget_id"]]

                # Sumber wajib berasal dari biro/entity lain, bukan dari pemilik target yang sama.
                if (source["entity_id"] == target["entity_id"]
                        and source["biro_id"] == target["biro_id"]):
                    return jsonify({"error": "Sumber realokasi harus berasal dari biro atau entity lain."}), 409

                if source["budget_year"] != target["budget_year"]:
                    return jsonify({"error": "Tahun anggaran sumber dan target harus sama."}), 409

                source_scope = str(source["budget_scope"] or "").strip().upper()
                target_scope = str(target["budget_scope"] or "").strip().upper()
                if source_scope != target_scope:
                    return jsonify({"error": "Budget Scope sumber dan target harus sama."}), 409

                if target_scope == "CI_ONLY":
                    if source["commitment_item_id"] != target["commitment_item_id"]:
                        return jsonify({"error": "Realokasi CI_ONLY hanya diperbolehkan untuk Commitment Item yang sama."}), 409
                elif target_scope == "FC_CI":
                    if (source["funds_center_id"] != target["funds_center_id"]
                            or source["commitment_item_id"] != target["commitment_item_id"]):
                        return jsonify({"error": "Realokasi FC_CI hanya diperbolehkan untuk kombinasi Funds Center dan Commitment Item yang sama."}), 409
                else:
                    return jsonify({"error": "Budget Scope target tidak dikenali."}), 409

                source_available = Decimal(str(source["available_amount"]))
                live_shortage = max(Decimal("0"), Decimal(str(req["request_amount"])) - Decimal(str(target["available_amount"])))
                if live_shortage <= 0:
                    return jsonify({"error": "Available Budget target saat ini sudah mencukupi. Realokasi tidak diperlukan."}), 409
                target_hold = Decimal(str(target["current_budget"])) - Decimal(str(target["consumable_budget"]))
                if target_hold >= live_shortage:
                    return jsonify({"error": "Approval Hold target masih mencukupi. Gunakan Open Budget, bukan Reallocation."}), 409
                if source_available < amount:
                    return jsonify({"error": f"Nominal melebihi Available Budget sumber. Maksimal {source_available:.2f}."}), 409
                if amount > live_shortage:
                    return jsonify({"error": f"Nominal melebihi shortage target saat ini. Maksimal yang diperlukan {live_shortage:.2f}."}), 409

                src_old = {k: Decimal(str(source[k])) for k in ("current_budget", "consumable_budget", "available_amount")}
                tgt_old = {k: Decimal(str(target[k])) for k in ("current_budget", "consumable_budget", "available_amount")}
                src_new = {k: src_old[k] - amount for k in src_old}
                tgt_new = {k: tgt_old[k] + amount for k in tgt_old}
                if any(v < 0 for v in src_new.values()):
                    return jsonify({"error": "Hasil realokasi membuat saldo sumber negatif."}), 409

                cursor.execute("""
                    UPDATE public.budget_master
                    SET current_budget = %s, consumable_budget = %s, available_amount = %s
                    WHERE budget_id = %s
                """, (src_new["current_budget"], src_new["consumable_budget"],
                      src_new["available_amount"], source_id))
                cursor.execute("""
                    UPDATE public.budget_master
                    SET current_budget = %s, consumable_budget = %s, available_amount = %s
                    WHERE budget_id = %s
                """, (tgt_new["current_budget"], tgt_new["consumable_budget"],
                      tgt_new["available_amount"], req["budget_id"]))

                remaining_shortage = max(Decimal("0"), Decimal(str(req["request_amount"])) - tgt_new["available_amount"])
                fully_covered = remaining_shortage == 0
                cursor.execute("""
                    UPDATE public.budget_request
                    SET request_status = %s, budget_status = %s
                    WHERE request_id = %s
                """, ("Approved" if fully_covered else "Pending",
                      "Budget Cukup" if fully_covered else "Realokasi", request_id))

                _approval_record_decision(cursor, request_id, "Approve with Reallocation", amount, instruction)
                allocation_type = "Reallocation FC_CI" if target["budget_scope"] == "FC_CI" else "Reallocation CI_Only"
                cursor.execute("""
                    INSERT INTO public.budget_allocation
                        (request_id, source_budget_id, target_budget_id,
                         allocation_type, amount, instruction, approved_by)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (request_id, source_id, req["budget_id"], allocation_type,
                      amount, instruction, session["user_id"]))

                for field in ("current_budget", "consumable_budget", "available_amount"):
                    _approval_record_history(cursor, source_id, request_id,
                        "Reallocation Out", field, src_old[field], src_new[field], amount)
                    _approval_record_history(cursor, req["budget_id"], request_id,
                        "Reallocation In", field, tgt_old[field], tgt_new[field], amount)

        return jsonify({
            "message": "Approve with Reallocation Budget berhasil diproses.",
            "request_status": "Approved" if fully_covered else "Pending",
            "budget_status": "Budget Cukup" if fully_covered else "Realokasi",
            "allocated_amount": str(amount),
            "remaining_shortage": str(remaining_shortage)
        })
    except psycopg2.Error:
        app.logger.exception("Gagal memproses realokasi budget")
        return jsonify({"error": "Reallocation gagal diproses. Tidak ada perubahan yang disimpan."}), 500
    finally:
        if conn is not None:
            conn.close()


def _budget_export_file(user_mode=False, request_id=None):
    """Export template budget untuk sisi Approval."""
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            where = []
            params = []
            if user_mode:
                where.append("br.user_id = %s")
                params.append(session["user_id"])
            if request_id is not None:
                where.append("br.request_id = %s")
                params.append(request_id)

            where_sql = (" WHERE " + " AND ".join(where)) if where else ""

            cursor.execute(f"""
                SELECT
                    br.request_id,
                    br.request_date,
                    br.transaction_date,
                    br.pic,
                    br.input_profit_center,
                    br.input_gl_account,
                    br.request_amount,
                    br.request_description,
                    br.input_cost_center,
                    br.mapped_fund_id,
                    br.mapped_funds_center_id,
                    br.mapped_commitment_item_id,
                    f.fund_code,
                    fc.funds_center_code,
                    ci.commitment_item_code,
                    u.username,
                    ue.unit_entity,
                    br.request_status
                FROM public.budget_request br
                JOIN public.users u ON u.user_id = br.user_id
                LEFT JOIN public.unit_entity ue ON ue.entity_id = br.entity_id
                LEFT JOIN public.fund f ON f.fund_id = br.mapped_fund_id
                LEFT JOIN public.funds_center fc
                    ON fc.funds_center_id = br.mapped_funds_center_id
                LEFT JOIN public.commitment_item ci
                    ON ci.commitment_item_id = br.mapped_commitment_item_id
                {where_sql}
                ORDER BY br.request_date, br.request_id
            """, params)
            requests_data = cursor.fetchall()
            request_ids = [r["request_id"] for r in requests_data]

            allocations = []
            decisions = []
            if request_ids:
                cursor.execute("""
                    SELECT
                        ba.request_id,
                        COALESCE(br_target.transaction_date, br_target.request_date)::date
                            AS allocation_date,
                        ba.amount,
                        ba.instruction,
                        ba.allocation_type,
                        sf.fund_code AS source_fund,
                        sfc.funds_center_code AS source_fc,
                        sci.commitment_item_code AS source_ci,
                        tf.fund_code AS target_fund,
                        tfc.funds_center_code AS target_fc,
                        tci.commitment_item_code AS target_ci
                    FROM public.budget_allocation ba
                    LEFT JOIN public.budget_master sb
                        ON sb.budget_id = ba.source_budget_id
                    LEFT JOIN LATERAL (
                        SELECT br_source.mapped_fund_id
                        FROM public.budget_request br_source
                        WHERE br_source.budget_id = sb.budget_id
                          AND br_source.mapped_fund_id IS NOT NULL
                        ORDER BY br_source.request_date DESC,
                                 br_source.request_id DESC
                        LIMIT 1
                    ) source_fund_map ON TRUE
                    LEFT JOIN public.fund sf
                        ON sf.fund_id = source_fund_map.mapped_fund_id
                    LEFT JOIN public.funds_center sfc
                        ON sfc.funds_center_id = sb.funds_center_id
                    LEFT JOIN public.commitment_item sci
                        ON sci.commitment_item_id = sb.commitment_item_id
                    LEFT JOIN public.budget_master tb
                        ON tb.budget_id = ba.target_budget_id
                    LEFT JOIN public.budget_request br_target
                        ON br_target.request_id = ba.request_id
                    LEFT JOIN public.fund tf
                        ON tf.fund_id = br_target.mapped_fund_id
                    LEFT JOIN public.funds_center tfc
                        ON tfc.funds_center_id = tb.funds_center_id
                    LEFT JOIN public.commitment_item tci
                        ON tci.commitment_item_id = tb.commitment_item_id
                    WHERE ba.request_id = ANY(%s)
                    ORDER BY ba.request_id, ba.allocation_id
                """, (request_ids,))
                allocations = cursor.fetchall()

                cursor.execute("""
                    SELECT
                        ad.request_id,
                        ad.decision,
                        ad.approved_amount,
                        ad.decision_date,
                        ad.instruction,
                        f.fund_code,
                        fc.funds_center_code,
                        ci.commitment_item_code
                    FROM public.approval_decision ad
                    LEFT JOIN public.budget_request br
                        ON br.request_id = ad.request_id
                    LEFT JOIN public.budget_master bm
                        ON bm.budget_id = br.budget_id
                    LEFT JOIN public.fund f
                        ON f.fund_id = br.mapped_fund_id
                    LEFT JOIN public.funds_center fc
                        ON fc.funds_center_id = COALESCE(
                            br.mapped_funds_center_id, bm.funds_center_id
                        )
                    LEFT JOIN public.commitment_item ci
                        ON ci.commitment_item_id = COALESCE(
                            br.mapped_commitment_item_id, bm.commitment_item_id
                        )
                    WHERE ad.request_id = ANY(%s)
                    ORDER BY ad.request_id, ad.decision_date
                """, (request_ids,))
                decisions = cursor.fetchall()

        wb = Workbook()
        ws_a = wb.active
        ws_a.title = "APPROVEL"
        ws_u = wb.create_sheet("USER")

        # Sheet APPROVEL: enam kolom, tanpa kolom pemisah kosong.
        ws_a.append(["BUDGET"])
        ws_a.merge_cells("A1:F1")
        ws_a.append([
            "DATE", "INSTRUCTION", "FUND", "FUNDS CENTER",
            "COMMITMENT ITEM", "AMOUNT"
        ])
        ws_a.append([
            "(TANGGAL)", "(+/-) OPSIONAL", "(LINK COSTCENTER)",
            "(LINK COSTCENTER)", "(LINK G/L)", "(NOMINAL)"
        ])

        # Sheet USER: judul DATABASE memenuhi seluruh lebar tabel.
        ws_u.append(["DATABASE"])
        ws_u.merge_cells("A1:G1")
        ws_u.append([
            "DATE", "PIC", "PROFIT CENTER", "COST CENTER",
            "GL ACCOUNT", "AMOUNT", "KETERANGAN"
        ])
        ws_u.append([
            "(TANGGAL)", "(NAMA)", "(PROFIT CENTER)", "(COST CENTER)",
            "(KODE GL)", "(NOMINAL)", "(KETERANGAN PENGAJUAN)"
        ])

        # DATABASE: satu baris untuk setiap pengajuan.
        for r in requests_data:
            ws_u.append([
                r["transaction_date"] or r["request_date"],
                r["pic"] or r["username"],
                r["input_profit_center"],
                r["input_cost_center"],
                r["input_gl_account"],
                float(r["request_amount"] or 0),
                r["request_description"]
            ])

        allocations_by_request = {}
        for a in allocations:
            allocations_by_request.setdefault(a["request_id"], []).append(a)

        decisions_by_request = {}
        for d in decisions:
            decisions_by_request.setdefault(d["request_id"], []).append(d)

        # APPROVEL: transaksi aktual atau rancangan untuk pengajuan pending.
        for r in requests_data:
            rid = r["request_id"]
            request_allocations = allocations_by_request.get(rid, [])
            request_decisions = decisions_by_request.get(rid, [])
            status = str(r["request_status"] or "").strip().lower()
            request_date = r["transaction_date"] or r["request_date"]

            if request_allocations:
                for a in request_allocations:
                    dt = a["allocation_date"] or request_date
                    amount = float(a["amount"] or 0)
                    ws_a.append([
                        dt, "-", a["source_fund"], a["source_fc"],
                        a["source_ci"], amount
                    ])
                    ws_a.append([
                        dt, "+", a["target_fund"], a["target_fc"],
                        a["target_ci"], amount
                    ])
                continue

            if request_decisions:
                for d in request_decisions:
                    decision = str(d["decision"] or "").strip().lower()
                    if "reject" in decision:
                        continue
                    if "approve" in decision or "open budget" in decision:
                        ws_a.append([
                            d["decision_date"].date() if d["decision_date"] else request_date,
                            "+",
                            d["fund_code"] or r["fund_code"],
                            d["funds_center_code"] or r["funds_center_code"],
                            d["commitment_item_code"] or r["commitment_item_code"],
                            float(d["approved_amount"] or 0)
                        ])
                continue

            if "pending" in status:
                row_idx = ws_a.max_row + 1
                ws_a.append([
                    request_date, "+", r["fund_code"],
                    r["funds_center_code"], r["commitment_item_code"],
                    float(r["request_amount"] or 0)
                ])
                ws_a.cell(row=row_idx, column=2).comment = Comment(
                    "RANCANGAN PENGAJUAN PENDING — belum merupakan keputusan "
                    "Approval atau transaksi perubahan budget.",
                    "SILOG Budget Monitoring"
                )
                ws_a.cell(row=row_idx, column=6).comment = Comment(
                    "Nominal ini merupakan nominal pengajuan dari Pengusul, "
                    "bukan nominal yang sudah disetujui.",
                    "SILOG Budget Monitoring"
                )

        # Styling konsisten: judul, header, petunjuk, dan isi.
        title_fill = PatternFill("solid", fgColor="A80710")
        header_fill = PatternFill("solid", fgColor="C00000")
        instruction_fill = PatternFill("solid", fgColor="F2F3F5")
        alternate_fill = PatternFill("solid", fgColor="FAFAFA")
        white_bold = Font(name="Arial", size=14, bold=True, color="FFFFFF")
        header_font = Font(name="Arial", size=10, bold=True, color="FFFFFF")
        instruction_font = Font(name="Arial", size=9, italic=True, color="666666")
        body_font = Font(name="Arial", size=10, color="222222")
        thin = Side(style="thin", color="D9DEE7")
        table_border = Border(bottom=thin)

        sheet_configs = [
            (ws_a, 6, [16, 18, 20, 22, 24, 20], 6),
            (ws_u, 7, [16, 20, 20, 22, 20, 20, 48], 7),
        ]
        for ws, column_count, widths, amount_col in sheet_configs:
            # Judul baris pertama.
            title_cell = ws.cell(row=1, column=1)
            title_cell.fill = title_fill
            title_cell.font = white_bold
            title_cell.alignment = Alignment(
                horizontal="left", vertical="center", indent=1
            )
            ws.row_dimensions[1].height = 32
            for col in range(1, column_count + 1):
                ws.cell(row=1, column=col).fill = title_fill

            # Header baris kedua.
            for cell in ws[2][:column_count]:
                cell.fill = header_fill
                cell.font = header_font
                cell.alignment = Alignment(
                    horizontal="center", vertical="center", wrap_text=True
                )
                cell.border = table_border
            ws.row_dimensions[2].height = 28

            # Baris ketiga adalah petunjuk pengisian.
            for cell in ws[3][:column_count]:
                cell.fill = instruction_fill
                cell.font = instruction_font
                cell.alignment = Alignment(
                    horizontal="center", vertical="center", wrap_text=True
                )
                cell.border = table_border
            ws.row_dimensions[3].height = 32

            # Isi data mulai baris keempat.
            for row_idx in range(4, ws.max_row + 1):
                ws.row_dimensions[row_idx].height = 24
                for col_idx in range(1, column_count + 1):
                    cell = ws.cell(row=row_idx, column=col_idx)
                    cell.font = body_font
                    cell.border = table_border
                    cell.alignment = Alignment(
                        vertical="center",
                        horizontal=("right" if col_idx == amount_col else "left"),
                        wrap_text=(col_idx == column_count and ws.title == "USER")
                    )
                    if row_idx % 2 == 1:
                        cell.fill = alternate_fill
                    if col_idx == 1:
                        cell.number_format = "dd/mm/yyyy"
                    if col_idx == amount_col:
                        cell.number_format = '#,##0.00;[Red]-#,##0.00'

            for col_idx, width in enumerate(widths, start=1):
                ws.column_dimensions[get_column_letter(col_idx)].width = width

            ws.freeze_panes = "A4"
            ws.sheet_view.showGridLines = False
            ws.auto_filter.ref = (
                f"A2:{get_column_letter(column_count)}{ws.max_row}"
            )
            ws.sheet_properties.pageSetUpPr.fitToPage = True
            ws.page_setup.fitToWidth = 1
            ws.page_setup.fitToHeight = 0
            ws.page_setup.orientation = "landscape"

        output = BytesIO()
        wb.save(output)
        output.seek(0)

        suffix = f"_REQ_{request_id}" if request_id is not None else "_SEMUA"
        role_name = "pengusul" if user_mode else "approval"
        return send_file(
            output,
            as_attachment=True,
            download_name=f"template_budget_{role_name}{suffix}.xlsx",
            mimetype=(
                "application/vnd.openxmlformats-officedocument."
                "spreadsheetml.sheet"
            )
        )
    finally:
        if conn is not None:
            conn.close()


@app.route("/approval/export-budget.xlsx")
def export_budget_approval_all():
    guard = approval_api_guard()
    if guard is not None:
        return guard
    return _budget_export_file(user_mode=False)


@app.route("/approval/export-budget/<int:request_id>.xlsx")
def export_budget_approval_one(request_id):
    guard = approval_api_guard()
    if guard is not None:
        return guard
    return _budget_export_file(user_mode=False, request_id=request_id)

# menjalankan aplikasi flask lokal
if __name__ == "__main__":
    app.run(debug=True, port=5000)