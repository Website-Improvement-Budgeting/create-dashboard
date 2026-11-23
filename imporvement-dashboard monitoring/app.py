import os
import hmac
import hashlib
import secrets
from datetime import date, datetime
from decimal import Decimal, InvalidOperation

from io import BytesIO
from openpyxl import Workbook, load_workbook
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
from approval_engine_silog import execute_approval, budget_plan, ApprovalEngineError

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



# Read-only metrics untuk Tab Monitoring Approval.
# Tidak mengubah saldo, status request, maupun shared approval engine.
def get_dashboard_approval_monitor(budget_year, entity_id="all", biro_id="all"):
    from decimal import Decimal
    from psycopg2.extras import RealDictCursor
    from approval_engine_silog import budget_plan, ApprovalEngineError

    # Untuk request tanpa budget_id, gunakan tahun pengajuan agar tidak hilang
    # dari antrean; statusnya tetap "Mapping / Sumber Belum Valid".
    where = ["(bm.budget_year = %s OR (bm.budget_id IS NULL AND EXTRACT(YEAR FROM br.request_date) = %s))"]
    params = [budget_year, budget_year]
    if entity_id != "all":
        where.append("br.entity_id = %s")
        params.append(int(entity_id))
    if biro_id != "all":
        where.append("u.biro_id = %s")
        params.append(int(biro_id))
    clause = " AND ".join(where)
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(f"""
                SELECT br.request_id, br.request_status, br.request_date, br.request_amount,
                       br.mapping_status, br.budget_id, ue.unit_entity, b.biro_name,
                       bm.current_budget, bm.consumable_budget, bm.available_amount
                FROM public.budget_request br
                LEFT JOIN public.budget_master bm ON bm.budget_id = br.budget_id
                JOIN public.users u ON u.user_id = br.user_id
                LEFT JOIN public.unit_entity ue ON ue.entity_id = br.entity_id
                LEFT JOIN public.biro b ON b.biro_id = u.biro_id AND b.entity_id = br.entity_id
                WHERE {clause}
                ORDER BY br.request_date ASC, br.request_id ASC
            """, params)
            rows = cursor.fetchall()
        result = dict(pending=0, approved=0, rejected=0, shortage_count=0,
                      sufficient=0, open_needed=0, reallocation_review=0,
                      unmapped=0, pending_rows=[],
                      approved_amount=Decimal('0'),
                      open_budget_amount=Decimal('0'),
                      reallocation_amount=Decimal('0'))
        for row in rows:
            status = row['request_status']
            if status == 'Approved':
                result['approved'] += 1
                # Nominal request berstatus Approved. Ini bukan Consumed Budget
                # maupun field approved_amount pada histori decision lama.
                result['approved_amount'] += Decimal(str(row['request_amount'] or 0))
                continue
            if status == 'Rejected':
                result['rejected'] += 1
                continue
            if status != 'Pending':
                continue
            result['pending'] += 1
            condition, condition_class = 'Perlu Review', 'review'
            if row['mapping_status'] != 'Oke' or row['budget_id'] is None:
                result['unmapped'] += 1
                condition = 'Mapping Perlu Review'
            else:
                try:
                    plan = budget_plan(row['request_amount'],row['available_amount'],
                                       row['current_budget'],row['consumable_budget'])
                    if plan['shortage'] > Decimal('0'):
                        result['shortage_count'] += 1
                    if plan['mode'] == 'approve':
                        result['sufficient'] += 1
                        condition,condition_class = 'Budget Cukup','ok'
                    elif plan['mode'] == 'open':
                        result['open_needed'] += 1
                        condition,condition_class = 'Potensi Open Budget','open'
                    else:
                        result['reallocation_review'] += 1
                        condition = 'Perlu Realokasi / Review'
                except (ApprovalEngineError, ValueError, TypeError):
                    result['reallocation_review'] += 1
            if len(result['pending_rows']) < 12:
                result['pending_rows'].append(dict(row, condition=condition, condition_class=condition_class))
        # Rekapitulasi Open Budget dan Reallocation berasal dari alokasi
        # transaksi yang tercatat, bukan dari saldo budget atau budget_history.
        # Satu baris alokasi dihitung satu kali. Filter sama dengan KPI Approval.
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(f"""
                SELECT ba.allocation_type, COALESCE(SUM(ba.amount), 0) AS amount
                FROM public.budget_allocation ba
                JOIN public.budget_request br ON br.request_id = ba.request_id
                LEFT JOIN public.budget_master bm ON bm.budget_id = br.budget_id
                JOIN public.users u ON u.user_id = br.user_id
                WHERE {clause} AND br.request_status = 'Approved'
                GROUP BY ba.allocation_type
            """, params)
            for allocation in cursor.fetchall():
                amount = Decimal(str(allocation['amount'] or 0))
                allocation_type = allocation['allocation_type']
                if allocation_type == 'Open Budget':
                    result['open_budget_amount'] += amount
                elif allocation_type in ('Reallocation FC_CI', 'Reallocation CI_Only'):
                    result['reallocation_amount'] += amount
        return result
    finally:
        conn.close()

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

            approval_monitor = get_dashboard_approval_monitor(
                selected_year, selected_entity, selected_biro
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
                approval_monitor=approval_monitor,
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
        "Budget kurang, pengajuan memerlukan review Approval."
        if shortage > 0
        else "Budget mencukupi, pengajuan dapat direview Approval."
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



# =====================================================
# IMPORT EXCEL PENGAJUAN BUDGET (BATCH)
# =====================================================

PENGAJUAN_EXCEL_COLUMNS = [
    "Tanggal Transaksi", "Unit Entity", "PIC", "Profit Center",
    "Cost Center", "GL Account", "Nominal Pengajuan", "Keterangan"
]


def _pengajuan_excel_date(value):
    if hasattr(value, "date"):
        value = value.date()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, str):
        value = value.strip()
        # Menerima format ISO dan tanggal Indonesia.
        for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y"):
            try:
                return date.fromisoformat(value) .isoformat() if fmt == "%Y-%m-%d" else __import__("datetime").datetime.strptime(value, fmt).date().isoformat()
            except ValueError:
                pass
    raise PengajuanValidationError("Tanggal harus berupa tanggal Excel atau format DD/MM/YYYY.")


def _pengajuan_excel_entity_id(entity_value, entity_lookup):
    key = str(entity_value or "").strip().casefold()
    if not key:
        raise PengajuanValidationError("Unit Entity wajib diisi.")
    if key not in entity_lookup:
        raise PengajuanValidationError("Unit Entity tidak dikenali atau bukan bagian dari akses biro Anda.")
    return entity_lookup[key]


def _pengajuan_bulk_row_payload(row, entity_lookup):
    return {
        "tanggal": _pengajuan_excel_date(row.get("Tanggal Transaksi")),
        "entity_id": _pengajuan_excel_entity_id(row.get("Unit Entity"), entity_lookup),
        "pic": str(row.get("PIC") or "").strip(),
        "profit_center": str(row.get("Profit Center") or "").strip(),
        "cost_center": str(row.get("Cost Center") or "").strip(),
        "gl_account": str(row.get("GL Account") or "").strip(),
        "request_amount": str(row.get("Nominal Pengajuan") or "").strip(),
        "keterangan": str(row.get("Keterangan") or "").strip(),
    }


def _pengajuan_insert_one(cursor, user_id, payload, batch_id=None):
    data = pengajuan_parse_input(payload, require_details=True)
    result = pengajuan_check(cursor, user_id, data)
    mapped, budget = result["mapped"], result["budget"]
    if budget is None:
        raise PengajuanValidationError("Sumber budget tidak ditemukan. Pengajuan belum dapat dikirim.", 422)
    current = budget["current_budget"]
    consumable = budget["consumable_budget"]
    available = budget["available_amount"]
    if current is None or consumable is None or available is None:
        raise PengajuanValidationError("Data Current, Consumable, atau Available Budget belum lengkap.", 422)
    current, consumable, available = Decimal(str(current)), Decimal(str(consumable)), Decimal(str(available))
    if current < 0 or consumable < 0 or available < 0:
        raise PengajuanValidationError("Nilai budget tidak boleh negatif.", 422)
    if consumable > current:
        raise PengajuanValidationError("Consumable Budget melebihi Current Budget.", 422)
    if result["budget_status"] not in {"Budget Cukup", "Review"}:
        raise PengajuanValidationError("Status budget tidak sesuai dengan standar database.", 422)
    approval_hold = current - consumable
    cursor.execute("""
        INSERT INTO public.budget_request (
            batch_id,
            user_id, entity_id, request_date, transaction_date, pic,
            input_profit_center, input_cost_center, input_gl_account,
            request_amount, request_description,
            mapped_fund_id, mapped_funds_center_id, mapped_commitment_item_id,
            budget_id, budget_scope,
            available_amount_snapshot, shortage_amount, approval_hold_amount_snapshot,
            mapping_status, budget_status, request_status
        ) VALUES (
            %s,
            %s, %s, NOW(), %s, %s,
            %s, %s, %s,
            %s, %s,
            %s, %s, %s,
            %s, %s,
            %s, %s, %s,
            'Oke', %s, 'Pending'
        )
        RETURNING request_id
    """, (
        batch_id,
        user_id, data["entity_id"], data["transaction_date"], data["pic"],
        data["profit_center"], data["cost_center"], data["gl_account"],
        data["request_amount"], data["description"],
        mapped["fund"]["id"], mapped["funds_center"]["id"], mapped["commitment_item"]["id"],
        budget["budget_id"], budget["budget_scope"], available, result["shortage"], approval_hold,
        result["budget_status"]
    ))
    saved = cursor.fetchone()
    return {
        "request_id": saved["request_id"],
        "budget_status": result["budget_status"],
        "budget_scope": budget["budget_scope"],
        "shortage_amount": str(result["shortage"]) if result["shortage"] is not None else None,
        "request_amount": str(data["request_amount"]),
    }


@app.route("/pengajuan-budget/template-excel", methods=["GET"])
def pengajuan_template_excel():
    if not session.get("user_id") or session.get("role") != "Pengusul":
        return redirect(url_for("login"))
    wb = Workbook()
    ws = wb.active
    ws.title = "Data Pengajuan"
    ws.append(PENGAJUAN_EXCEL_COLUMNS)
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = "A1:H2"
    widths = [20, 28, 24, 20, 20, 20, 22, 48]
    from openpyxl.styles import Font, PatternFill, Alignment
    for idx, width in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(idx)].width = width
        cell = ws.cell(1, idx)
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="C8102E")
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    ws.row_dimensions[1].height = 30
    entities = get_pengusul_entity_options(session["user_id"])

    # Dropdown Unit Entity mengikuti hak akses entity milik pengusul.
    # Daftar disimpan pada sheet referensi tersembunyi agar pilihan
    # yang tersedia selalu berasal dari master SILOG, bukan ketikan bebas.
    from openpyxl.worksheet.datavalidation import DataValidation
    from openpyxl.comments import Comment
    from openpyxl.workbook.defined_name import DefinedName

    ref_ws = wb.create_sheet("Referensi")
    entity_names = [
        str(item.get("unit_entity", "")).strip()
        for item in entities
        if item.get("unit_entity") and str(item.get("unit_entity")).strip()
    ]
    entity_names = list(dict.fromkeys(entity_names))

    if entity_names:
        for row_no, entity_name in enumerate(entity_names, start=1):
            ref_ws.cell(row=row_no, column=1, value=entity_name)

        entity_range = f"'Referensi'!$A$1:$A${len(entity_names)}"
        defined_name = DefinedName(
            name="DaftarUnitEntity",
            attr_text=entity_range
        )

        # Kompatibilitas beberapa versi openpyxl:
        # 3.x menggunakan DefinedNameDict.add(), sedangkan versi lama
        # menggunakan DefinedNameList.append() / definedName.append().
        names_collection = wb.defined_names
        if hasattr(names_collection, "add"):
            try:
                names_collection.add(defined_name)
            except (AttributeError, TypeError):
                if hasattr(names_collection, "append"):
                    names_collection.append(defined_name)
                elif hasattr(names_collection, "definedName"):
                    names_collection.definedName.append(defined_name)
                else:
                    raise RuntimeError(
                        "Versi openpyxl tidak mendukung pembuatan named range."
                    )
        elif hasattr(names_collection, "append"):
            names_collection.append(defined_name)
        elif hasattr(names_collection, "definedName"):
            names_collection.definedName.append(defined_name)
        else:
            raise RuntimeError(
                "Versi openpyxl tidak mendukung pembuatan named range."
            )

        entity_validation = DataValidation(
            type="list",
            formula1="=DaftarUnitEntity",
            allow_blank=False
        )
        entity_validation.errorTitle = "Unit Entity tidak valid"
        entity_validation.error = "Pilih Unit Entity dari daftar dropdown."
        entity_validation.promptTitle = "Pilih Unit Entity"
        entity_validation.prompt = "Gunakan pilihan yang tersedia pada dropdown."
        entity_validation.showErrorMessage = True
        entity_validation.showInputMessage = True
        ws.add_data_validation(entity_validation)
        entity_validation.add("B2:B1048576")
    else:
        # Jika pengusul tidak memiliki pilihan entity, jangan membuat
        # dropdown kosong yang memberi kesan data bisa dipilih.
        ws["B2"].comment = Comment(
            "Tidak ada Unit Entity yang tersedia untuk akun ini. Hubungi administrator.",
            "SILOG"
        )

    ref_ws.sheet_state = "hidden"

    # Contoh format pada baris input pertama; baris berikutnya tetap
    # mengikuti format tanggal/angka yang dibaca dari Excel saat import.
    ws["A2"].number_format = "dd/mm/yyyy"
    ws["G2"].number_format = '#,##0'

    info = wb.create_sheet("Petunjuk")
    instructions = [
        ["PETUNJUK PENGISIAN TEMPLATE PENGAJUAN BUDGET"],
        ["Isi satu baris untuk satu pengajuan. Mulai pengisian pada baris kedua di sheet Data Pengajuan."],
        ["Tanggal Transaksi", "Gunakan tanggal Excel atau format DD/MM/YYYY."],
        ["Unit Entity", "Pilih Unit Entity melalui dropdown pada kolom B di sheet Data Pengajuan. Pilihan mengikuti akses akun pengusul."],
        ["PIC", "Nama penanggung jawab wajib diisi."],
        ["Profit Center / Cost Center / GL Account", "Isi kode master yang valid, sistem akan melakukan mapping ulang."],
        ["Nominal Pengajuan", "Isi angka Rupiah bulat positif tanpa mengetik Rp."],
        ["Keterangan", "Wajib diisi, maksimal 2.000 karakter."],
        ["Batas upload", "Tidak ada batas jumlah baris. Ukuran file maksimal 20 MB."],
        ["Catatan", "Import tidak melewati validasi. Setiap baris diperiksa mapping dan ketersediaan budget sebelum dikirim."]
    ]
    for row in instructions:
        info.append(row)
    info.column_dimensions["A"].width = 34
    info.column_dimensions["B"].width = 110
    info["A1"].font = Font(bold=True, color="C8102E", size=14)
    for row in info.iter_rows(min_row=3, max_col=2):
        row[0].font = Font(bold=True)
    output = BytesIO()
    wb.save(output)
    output.seek(0)
    return send_file(output, as_attachment=True, download_name="Template_Pengajuan_Budget_SILOG.xlsx", mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@app.route("/api/pengajuan/import/preview", methods=["POST"])
def pengajuan_import_preview():
    guard = pengajuan_api_guard()
    if guard is not None:
        return guard
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename.lower().endswith(".xlsx"):
        return jsonify({"error": "Pilih file Excel berformat .xlsx."}), 400
    raw = uploaded.read(20 * 1024 * 1024 + 1)
    if len(raw) > 20 * 1024 * 1024:
        return jsonify({"error": "Ukuran file maksimal 20 MB."}), 413
    try:
        wb = load_workbook(BytesIO(raw), read_only=True, data_only=True)
        ws = wb["Data Pengajuan"] if "Data Pengajuan" in wb.sheetnames else wb.active
        headers = [str(c.value or "").strip() for c in next(ws.iter_rows(min_row=1, max_row=1))]
        if headers != PENGAJUAN_EXCEL_COLUMNS:
            return jsonify({"error": "Header kolom tidak sesuai template SILOG. Unduh template terbaru."}), 422
        entity_options = get_pengusul_entity_options(session["user_id"])
        entity_lookup = {str(e["unit_entity"]).strip().casefold(): e["entity_id"] for e in entity_options}
        parsed = []
        for excel_row, values in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
            if not any(v is not None and str(v).strip() for v in values):
                continue
            source = dict(zip(headers, values))
            item = {"row": excel_row, "payload": None, "status": "Gagal", "message": ""}
            try:
                payload = _pengajuan_bulk_row_payload(source, entity_lookup)
                data = pengajuan_parse_input(payload, require_details=True)
                conn = get_db_connection()
                try:
                    with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                        checked = pengajuan_check(cursor, session["user_id"], data)
                    if checked["budget"] is None:
                        raise PengajuanValidationError("Sumber budget tidak ditemukan.", 422)
                    item.update({"payload": payload, "status": "Siap", "message": checked["message"], "budget_status": checked["budget_status"], "shortage_amount": str(checked["shortage"]) if checked["shortage"] is not None else None})
                finally:
                    conn.close()
            except PengajuanValidationError as exc:
                item["message"] = str(exc)
            except psycopg2.Error:
                app.logger.exception("Validasi baris import gagal")
                item["message"] = "Gagal memeriksa data ke database."
            parsed.append(item)
        if not parsed:
            return jsonify({"error": "File tidak berisi baris pengajuan."}), 422
        original_filename = str(uploaded.filename or "").replace("\\", "/").rsplit("/", 1)[-1][:255]
        return jsonify({"success": True, "filename": original_filename, "total": len(parsed), "ready": sum(1 for x in parsed if x["status"] == "Siap"), "failed": sum(1 for x in parsed if x["status"] != "Siap"), "rows": parsed})
    except (ValueError, KeyError, OSError):
        return jsonify({"error": "File Excel tidak dapat dibaca. Pastikan menggunakan template SILOG."}), 422


@app.route("/api/pengajuan/import/submit", methods=["POST"])
def pengajuan_import_submit():
    guard = pengajuan_api_guard()
    if guard is not None:
        return guard

    payload = request.get_json(silent=True) or {}
    rows = payload.get("rows")
    if not isinstance(rows, list) or not rows:
        return jsonify({"error": "Data import tidak valid atau kosong."}), 400

    # Nama file hanya metadata. Hilangkan path agar tidak menyimpan path lokal klien.
    uploaded_filename = str(payload.get("filename") or "").replace("\\", "/").rsplit("/", 1)[-1][:255] or None

    results = []
    batch_id = None
    batch_code = None

    for item in rows:
        excel_row = item.get("row") if isinstance(item, dict) else None
        row_payload = item.get("payload") if isinstance(item, dict) else None
        outcome = {"row": excel_row, "status": "Gagal", "message": ""}
        conn = None
        candidate_batch_id = batch_id
        candidate_batch_code = batch_code

        try:
            # Validasi bentuk payload sebelum membuka transaksi.
            pengajuan_parse_input(row_payload, require_details=True)
            conn = get_db_connection()

            # Satu transaksi per baris mempertahankan perilaku partial success.
            # Batch pertama dibuat di transaksi yang sama dengan request pertama
            # yang berhasil, sehingga tidak akan tertinggal batch kosong.
            with conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                    if candidate_batch_id is None:
                        candidate_batch_code = (
                            f"BXL-{date.today():%Y%m%d}-{secrets.token_hex(4).upper()}"
                        )
                        cursor.execute("""
                            INSERT INTO public.budget_request_batch (
                                batch_code, user_id, uploaded_filename
                            )
                            VALUES (%s, %s, %s)
                            RETURNING batch_id
                        """, (
                            candidate_batch_code,
                            session["user_id"],
                            uploaded_filename
                        ))
                        candidate_batch_id = cursor.fetchone()["batch_id"]

                    saved = _pengajuan_insert_one(
                        cursor,
                        session["user_id"],
                        row_payload,
                        batch_id=candidate_batch_id
                    )

            # Tetapkan batch di memori hanya setelah transaksi baris commit.
            batch_id = candidate_batch_id
            batch_code = candidate_batch_code
            outcome.update({
                "status": "Terkirim",
                "message": f"ID Pengajuan: {saved['request_id']} — berhasil dikirim.",
                **saved
            })

        except PengajuanValidationError as exc:
            outcome["message"] = str(exc)
        except psycopg2.Error:
            app.logger.exception("Gagal menyimpan baris import %s", excel_row)
            outcome["message"] = "Gagal menyimpan ke database."
        finally:
            if conn is not None:
                conn.close()

        results.append(outcome)

    sent = sum(1 for x in results if x["status"] == "Terkirim")
    failed = len(results) - sent
    return jsonify({
        "success": sent > 0,
        "batch_id": batch_id,
        "batch_code": batch_code,
        "filename": uploaded_filename,
        "total": len(results),
        "sent": sent,
        "failed": failed,
        "rows": results
    })



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

    where = ["br.batch_id IS NULL"]
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

        # Approved Amount bisnis adalah seluruh request yang disetujui.
        # Simpan nilai kolom historis secara terpisah, tanpa mengubah database.
        decision_items = []
        for decision_row in decisions:
            item = serialize(decision_row)
            item["stored_approved_amount_legacy"] = item["approved_amount"]
            item["approved_amount"] = (
                str(row["request_amount"])
                if row["request_status"] == "Approved"
                and decision_row["decision"] in (
                    "Approve", "Open Budget", "Approve with Reallocation"
                ) else "0"
            )
            decision_items.append(item)

        return jsonify({
            "request": serialize(row),
            "decisions": decision_items,
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


def _approval_consume_request(cursor, budget_id, request_id, request_amount,
                              old_consumed, old_available):
    """Konsumsi seluruh nominal pengajuan yang sudah dapat dipenuhi.

    Current Budget dan Consumable Budget tidak berubah pada tahap konsumsi.
    Fungsi dipanggil di dalam transaksi database endpoint Approval.
    """
    request_amount = Decimal(str(request_amount))
    old_consumed = Decimal(str(old_consumed))
    old_available = Decimal(str(old_available))

    if request_amount <= 0:
        raise ValueError("Request Amount harus lebih besar dari Rp0.")
    if old_available < request_amount:
        raise ValueError("Available Budget tidak mencukupi untuk konsumsi transaksi.")

    new_consumed = old_consumed + request_amount
    new_available = old_available - request_amount

    cursor.execute("""
        UPDATE public.budget_master
        SET consumed_budget = %s,
            available_amount = %s
        WHERE budget_id = %s
    """, (new_consumed, new_available, budget_id))

    _approval_record_history(
        cursor, budget_id, request_id, "Consume Budget",
        "consumed_budget", old_consumed, new_consumed, request_amount
    )
    _approval_record_history(
        cursor, budget_id, request_id, "Consume Budget",
        "available_amount", old_available, new_available, request_amount
    )

    return {
        "consumed_budget": new_consumed,
        "available_amount": new_available
    }


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
    guard = approval_mutation_guard()
    if guard is not None: return guard
    payload=request.get_json(silent=True) or {}
    instruction=str(payload.get('instruction') or '').strip()
    if len(instruction)>2000: return jsonify({'error':'Instruksi maksimal 2.000 karakter.'}),400
    conn=None
    try:
        conn=get_db_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                result=execute_approval(cur,session['user_id'],request_id,'approve',instruction=instruction)
        return jsonify(result)
    except (ApprovalEngineError,ValueError) as exc:
        if conn: conn.rollback()
        return jsonify({'error':str(exc)}),409
    except psycopg2.Error:
        if conn: conn.rollback()
        app.logger.exception('Approve satuan gagal')
        return jsonify({'error':'Approve gagal diproses. Tidak ada perubahan disimpan.'}),500
    finally:
        if conn: conn.close()

@app.route("/api/approval/history", methods=["GET"])
def api_approval_history():
    """Riwayat seluruh pengajuan satuan dan Excel yang sudah diputuskan."""
    guard = approval_api_guard()
    if guard is not None:
        return guard
    kind = request.args.get("kind", "ALL").upper().strip()
    status = request.args.get("status", "ALL").strip()
    keyword = request.args.get("q", "").strip()
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(max(request.args.get("per_page", 20, type=int), 5), 100)
    if kind not in {"ALL", "SATUAN", "BATCH"}:
        return jsonify({"error":"Filter jenis pengajuan tidak valid."}), 400
    if status not in {"ALL", "Approved", "Rejected"}:
        return jsonify({"error":"Filter status riwayat tidak valid."}), 400
    if len(keyword) > 150:
        return jsonify({"error":"Kata pencarian terlalu panjang."}), 400

    where = ["br.request_status IN ('Approved','Rejected')"]
    params = []
    if kind == "SATUAN":
        where.append("br.batch_id IS NULL")
    elif kind == "BATCH":
        where.append("br.batch_id IS NOT NULL")
    if status != "ALL":
        where.append("br.request_status = %s")
        params.append(status)
    if keyword:
        where.append("""(
            CAST(br.request_id AS TEXT) ILIKE %s
            OR COALESCE(br.pic,'') ILIKE %s
            OR COALESCE(br.request_description,'') ILIKE %s
            OR COALESCE(u.username,'') ILIKE %s
            OR COALESCE(bb.batch_code,'') ILIKE %s
        )""")
        params.extend([f"%{keyword}%"]*5)
    where_sql = " AND ".join(where)
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(f"""
                SELECT COUNT(*)::integer AS total
                FROM public.budget_request br
                JOIN public.users u ON u.user_id=br.user_id
                LEFT JOIN public.budget_request_batch bb ON bb.batch_id=br.batch_id
                WHERE {where_sql}
            """, params)
            total = cursor.fetchone()["total"]
            cursor.execute(f"""
                SELECT br.request_id, br.batch_id, bb.batch_code,
                       bb.uploaded_filename, br.request_date, br.pic,
                       br.request_amount, br.request_description,
                       br.request_status, br.budget_status,
                       u.username AS requester_username,
                       ue.unit_entity, b.biro_name,
                       latest_decision.decision AS approval_decision,
                       latest_decision.decision_date
                FROM public.budget_request br
                JOIN public.users u ON u.user_id=br.user_id
                LEFT JOIN public.budget_request_batch bb ON bb.batch_id=br.batch_id
                LEFT JOIN public.unit_entity ue ON ue.entity_id=br.entity_id
                LEFT JOIN public.biro b ON b.biro_id=u.biro_id AND b.entity_id=br.entity_id
                LEFT JOIN LATERAL (
                    SELECT ad.decision, ad.decision_date
                    FROM public.approval_decision ad
                    WHERE ad.request_id=br.request_id
                    ORDER BY ad.decision_date DESC, ad.approval_id DESC
                    LIMIT 1
                ) latest_decision ON TRUE
                WHERE {where_sql}
                ORDER BY COALESCE(latest_decision.decision_date, br.request_date) DESC,
                         br.request_id DESC
                LIMIT %s OFFSET %s
            """, params+[per_page,(page-1)*per_page])
            rows=cursor.fetchall()
        items=[]
        for row in rows:
            item={}
            for key,value in row.items():
                if isinstance(value, Decimal): item[key]=str(value)
                elif hasattr(value,"isoformat"): item[key]=value.isoformat()
                else: item[key]=value
            items.append(item)
        return jsonify({"items":items,"pagination":{"page":page,"per_page":per_page,
            "total":total,"pages":(total+per_page-1)//per_page}})
    except psycopg2.Error:
        app.logger.exception("Gagal memuat riwayat Approval")
        return jsonify({"error":"Gagal memuat riwayat Approval."}),500
    finally:
        if conn is not None: conn.close()


@app.route("/api/approval/batches", methods=["GET"])
def api_approval_batches():
    """Daftar batch yang benar-benar berasal dari import Excel."""
    guard = approval_api_guard()
    if guard is not None:
        return guard

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
                SELECT
                    bb.batch_id,
                    bb.batch_code,
                    bb.uploaded_filename,
                    MIN(br.request_date) AS batch_date,
                    COUNT(br.request_id)::integer AS total_requests,
                    COUNT(*) FILTER (WHERE br.request_status = 'Pending')::integer AS pending,
                    COUNT(*) FILTER (WHERE br.request_status = 'Approved')::integer AS approved,
                    COUNT(*) FILTER (WHERE br.request_status = 'Rejected')::integer AS rejected,
                    COALESCE(SUM(br.request_amount), 0) AS total_amount,
                    MIN(ad_first.first_decision_date) AS first_decision_date
                FROM public.budget_request_batch bb
                JOIN public.budget_request br ON br.batch_id = bb.batch_id
                LEFT JOIN (
                    SELECT request_id, MIN(decision_date) AS first_decision_date
                    FROM public.approval_decision
                    GROUP BY request_id
                ) ad_first ON ad_first.request_id = br.request_id
                GROUP BY bb.batch_id, bb.batch_code, bb.uploaded_filename
                ORDER BY
                    CASE WHEN COUNT(*) FILTER (WHERE br.request_status = 'Pending') > 0
                         THEN 0 ELSE 1 END ASC,
                    CASE WHEN COUNT(*) FILTER (WHERE br.request_status = 'Pending') > 0
                         THEN MIN(br.request_date) END ASC NULLS LAST,
                    MIN(ad_first.first_decision_date) ASC NULLS LAST,
                    bb.batch_id ASC
            """)
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
        return jsonify({"items": items, "total": len(items)})
    except psycopg2.Error:
        app.logger.exception("Gagal memuat daftar batch approval")
        return jsonify({"error": "Daftar Batch Approval gagal dimuat."}), 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/api/approval/batches/<int:batch_id>", methods=["GET"])
def api_approval_batch_detail(batch_id):
    """Seluruh pengajuan yang menjadi anggota satu batch Excel."""
    guard = approval_api_guard()
    if guard is not None:
        return guard

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
                SELECT batch_id, batch_code, uploaded_filename
                FROM public.budget_request_batch
                WHERE batch_id = %s
            """, (batch_id,))
            batch = cursor.fetchone()
            if not batch:
                return jsonify({"error": "Batch tidak ditemukan."}), 404

            cursor.execute("""
                SELECT
                    br.request_id,
                    br.request_date,
                    br.request_amount,
                    br.shortage_amount,
                    br.budget_status,
                    br.request_status,
                    br.pic,
                    u.username AS requester_username,
                    ue.unit_entity,
                    b.biro_name,
                    ci.commitment_item_code,
                    ci.commitment_item_name,
                    latest_decision.decision AS approval_decision
                FROM public.budget_request br
                JOIN public.users u ON u.user_id = br.user_id
                LEFT JOIN public.unit_entity ue ON ue.entity_id = br.entity_id
                LEFT JOIN public.biro b
                    ON b.biro_id = u.biro_id AND b.entity_id = br.entity_id
                LEFT JOIN public.commitment_item ci
                    ON ci.commitment_item_id = br.mapped_commitment_item_id
                LEFT JOIN LATERAL (
                    SELECT ad.decision
                    FROM public.approval_decision ad
                    WHERE ad.request_id = br.request_id
                    ORDER BY ad.decision_date DESC, ad.approval_id DESC
                    LIMIT 1
                ) latest_decision ON TRUE
                WHERE br.batch_id = %s
                ORDER BY br.request_id ASC
            """, (batch_id,))
            rows = cursor.fetchall()

        def serialize(row):
            item = {}
            for key, value in row.items():
                if isinstance(value, Decimal):
                    item[key] = str(value)
                elif hasattr(value, "isoformat"):
                    item[key] = value.isoformat()
                else:
                    item[key] = value
            return item

        batch_data = serialize(batch)
        request_items = [serialize(row) for row in rows]
        return jsonify({"batch": batch_data, "items": request_items, "total": len(request_items)})
    except psycopg2.Error:
        app.logger.exception("Gagal memuat detail batch approval %s", batch_id)
        return jsonify({"error": "Detail Batch Approval gagal dimuat."}), 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/api/approval/requests/batch-approve", methods=["POST"])
def api_approval_batch_approve():
    guard=approval_mutation_guard()
    if guard is not None: return guard
    payload=request.get_json(silent=True) or {}
    raw_ids=payload.get('request_ids')
    raw_batch=payload.get('batch_id')
    instruction=str(payload.get('instruction') or '').strip()
    if not isinstance(raw_ids,list) or not raw_ids or len(raw_ids)>200:
        return jsonify({'error':'Pilih 1 sampai 200 pengajuan.'}),400
    if len(instruction)>2000: return jsonify({'error':'Instruksi maksimal 2.000 karakter.'}),400
    if raw_batch is not None and (isinstance(raw_batch,bool) or not str(raw_batch).isdigit()):
        return jsonify({'error':'Batch ID tidak valid.'}),400
    if any(isinstance(v,bool) or not str(v).isdigit() or int(v)<=0 for v in raw_ids):
        return jsonify({'error':'Request ID tidak valid.'}),400
    ids=[int(x) for x in raw_ids]
    if len(set(ids))!=len(ids): return jsonify({'error':'Request ID duplikat.'}),400
    conn=None
    try:
        conn=get_db_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Lock seluruh request terlebih dahulu, agar tidak ada transaksi lain
                # mengubah status saat batch sedang diproses.
                cur.execute('SELECT request_id FROM public.budget_request WHERE request_id=ANY(%s) ORDER BY request_id FOR UPDATE',(sorted(ids),))
                if len(cur.fetchall())!=len(ids): raise ApprovalEngineError('Salah satu pengajuan tidak ditemukan.')
                results=[execute_approval(cur,session['user_id'],rid,'approve',instruction=instruction,
                             expected_batch_id=int(raw_batch) if raw_batch is not None else None)
                         for rid in sorted(ids)]
        return jsonify({'message':f'{len(results)} pengajuan berhasil disetujui dalam satu Batch Approval.',
                        'request_status':'Approved','approved_count':len(results),
                        'approved':[{'request_id':r['request_id'],'approved_amount':r['approved_amount']} for r in results]})
    except (ApprovalEngineError,ValueError) as exc:
        if conn: conn.rollback()
        return jsonify({'error':str(exc)}),409
    except psycopg2.Error:
        if conn: conn.rollback()
        app.logger.exception('Batch approve gagal')
        return jsonify({'error':'Batch Approval gagal. Tidak ada perubahan disimpan.'}),500
    finally:
        if conn: conn.close()

@app.route("/api/approval/requests/<int:request_id>/open-budget", methods=["POST"])
def api_approval_open_budget(request_id):
    guard=approval_mutation_guard()
    if guard is not None: return guard
    payload=request.get_json(silent=True) or {}
    try: amount=_approval_decimal(payload.get('amount'),'Nominal Open Budget')
    except ValueError as exc: return jsonify({'error':str(exc)}),400
    instruction=str(payload.get('instruction') or '').strip()
    if len(instruction)>2000: return jsonify({'error':'Instruksi maksimal 2.000 karakter.'}),400
    conn=None
    try:
        conn=get_db_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                result=execute_approval(cur,session['user_id'],request_id,'open',instruction=instruction,open_amount=amount)
        return jsonify(result)
    except (ApprovalEngineError,ValueError) as exc:
        if conn: conn.rollback()
        return jsonify({'error':str(exc)}),409
    except psycopg2.Error:
        if conn: conn.rollback()
        app.logger.exception('Open Budget gagal')
        return jsonify({'error':'Open Budget gagal. Tidak ada perubahan disimpan.'}),500
    finally:
        if conn: conn.close()

@app.route("/api/approval/requests/<int:request_id>/reallocate", methods=["POST"])
def api_approval_reallocate(request_id):
    guard=approval_mutation_guard()
    if guard is not None: return guard
    payload=request.get_json(silent=True) or {}
    raw=payload.get('allocations')
    if not isinstance(raw,list) or not raw:
        raw=[{'source_budget_id':payload.get('source_budget_id'),
              'amount':payload.get('amount'),'allocation_date':payload.get('allocation_date'),
              'instruction':payload.get('instruction','')}]
    if len(raw)>50: return jsonify({'error':'Maksimal 50 baris realokasi.'}),400
    instruction=str(payload.get('instruction') or '').strip()
    if len(instruction)>2000: return jsonify({'error':'Instruksi maksimal 2.000 karakter.'}),400
    try:
        allocs=[]
        for idx,item in enumerate(raw,1):
            if not isinstance(item,dict): raise ValueError(f'Baris {idx} tidak valid.')
            bid=item.get('source_budget_id')
            if isinstance(bid,bool) or not str(bid or '').isdigit() or int(bid)<=0:
                raise ValueError(f'Sumber budget pada baris {idx} wajib dipilih.')
            dt=date.fromisoformat(str(item.get('allocation_date') or ''))
            allocs.append({**item,'source_budget_id':int(bid),
                           'amount':_approval_decimal(item.get('amount'),f'Nominal baris {idx}'),
                           'allocation_date':dt})
    except (ValueError,TypeError) as exc:
        return jsonify({'error':str(exc)}),400
    conn=None
    try:
        conn=get_db_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                result=execute_approval(cur,session['user_id'],request_id,'reallocate',allocations=allocs,instruction=instruction)
        return jsonify(result)
    except (ApprovalEngineError,ValueError) as exc:
        if conn: conn.rollback()
        return jsonify({'error':str(exc)}),409
    except psycopg2.Error:
        if conn: conn.rollback()
        app.logger.exception('Reallocation gagal')
        return jsonify({'error':'Reallocation gagal. Tidak ada perubahan disimpan.'}),500
    finally:
        if conn: conn.close()

# ============================================================
# APPROVAL EXCEL IMPORT: UPLOAD -> PREVIEW -> CONFIRM
# Partial success per Request ID. Invalid rows remain Pending.
# ============================================================

@app.route("/api/approval/batches/<int:batch_id>/upload", methods=["POST"])
def api_approval_excel_upload(batch_id):
    guard = approval_mutation_guard()
    if guard is not None:
        return guard

    conn = None
    file = request.files.get("file")
    if not file or not file.filename or not file.filename.lower().endswith(".xlsx"):
        return jsonify({"error": "Pilih file template Approval berformat .xlsx."}), 400

    raw = file.read(15 * 1024 * 1024 + 1)
    if len(raw) > 15 * 1024 * 1024:
        return jsonify({"error": "Ukuran file maksimal 15 MB."}), 413

    filename = file.filename.replace("\\", "/").rsplit("/", 1)[-1][:255]
    digest = hashlib.sha256(raw).hexdigest()
    parsed_rows = []
    try:
        wb = load_workbook(BytesIO(raw), read_only=True, data_only=True)
        required_sheets = {"APPROVAL", "REQUEST_MAP"}
        if not required_sheets.issubset(set(wb.sheetnames)):
            return jsonify({"error": "Sheet APPROVAL dan REQUEST_MAP wajib tersedia. Unduh template terbaru."}), 422

        ws = wb["APPROVAL"]
        header_row = None
        for rn in range(1, min(ws.max_row or 1, 10) + 1):
            headers = [str(ws.cell(rn, c).value or "").strip().upper() for c in range(1, 8)]
            if headers[0:5] == ["DATE", "INSTRUCTION", "FUND", "FUNDS CENTER", "COMMITMENT ITEM"] and headers[6] == "AMOUNT":
                header_row = rn
                break
        if not header_row:
            return jsonify({"error": "Susunan kolom sheet APPROVAL tidak sesuai template SILOG."}), 422

        map_ws = wb["REQUEST_MAP"]
        map_headers = [str(c.value or "").strip().upper() for c in next(map_ws.iter_rows(min_row=1, max_row=1))]
        if map_headers[:5] != ["REQUEST ID", "BATCH ID", "STATUS", "APPROVAL ROW START", "APPROVAL ROW END"]:
            return jsonify({"error": "Susunan kolom REQUEST_MAP tidak sesuai template SILOG."}), 422

        mappings = []
        seen_ids = set()
        for vals in map_ws.iter_rows(min_row=2, values_only=True):
            if not vals or vals[0] in (None, ""):
                continue
            try:
                rid, map_batch = int(vals[0]), int(vals[1])
                row_start, row_end = int(vals[3]), int(vals[4])
            except (TypeError, ValueError, IndexError):
                return jsonify({"error": "REQUEST_MAP berisi Request ID, Batch ID, atau rentang baris yang tidak valid."}), 422
            if rid in seen_ids or row_start < header_row + 1 or row_end < row_start:
                return jsonify({"error": f"REQUEST_MAP duplikat atau rentang baris tidak valid untuk Request ID {rid}."}), 422
            seen_ids.add(rid)
            mappings.append({"request_id": rid, "batch_id": map_batch, "start": row_start, "end": row_end})

        if not mappings:
            return jsonify({"error": "REQUEST_MAP tidak berisi pengajuan."}), 422

        # A row may belong to exactly one Request ID; overlapping ranges are ambiguous.
        occupied_rows = {}
        for mapping in mappings:
            if mapping["end"] > (ws.max_row or header_row):
                return jsonify({"error": f"Rentang APPROVAL untuk REQ-{mapping['request_id']} melebihi jumlah baris."}), 422
            for excel_row in range(mapping["start"], mapping["end"] + 1):
                if excel_row in occupied_rows:
                    return jsonify({"error": f"Rentang APPROVAL tumpang tindih antara REQ-{occupied_rows[excel_row]} dan REQ-{mapping['request_id']}."}), 422
                occupied_rows[excel_row] = mapping["request_id"]

        for rn in range(header_row + 1, (ws.max_row or header_row) + 1):
            vals = [ws.cell(rn, c).value for c in range(1, 8)]
            if not any(v not in (None, "") for v in vals):
                continue
            dt, instruction, fund, fc, ci, source_entity_raw, amount_raw = vals
            source_biro_raw = ws.cell(rn, 8).value

            # Baris petunjuk pada template (mis. "(TANGGAL)", "(+/-) OPSIONAL",
            # "(LINK COSTCENTER)", "(LINK G/L)", "(NOMINAL)") bukan transaksi.
            # Abaikan baris tersebut sebelum mencari REQUEST_MAP agar tidak tampil
            # sebagai orphan/invalid row pada Preview.
            instruction_text = str(instruction or "").strip()
            placeholder_values = {
                str(v or "").strip().upper()
                for v in (dt, instruction, fund, fc, ci, amount_raw)
                if v not in (None, "")
            }
            is_instruction_guide = (
                instruction_text.upper() not in ("+", "-")
                and any(
                    token in placeholder_values
                    for token in ("(TANGGAL)", "(+/-) OPSIONAL", "(LINK COSTCENTER)",
                                  "(LINK G/L)", "(NOMINAL)")
                )
            )
            if is_instruction_guide:
                continue
            mapping = next((m for m in mappings if m["start"] <= rn <= m["end"]), None)
            item = {
                "request_id": mapping["request_id"] if mapping else None,
                "excel_row_number": rn,
                "instruction": str(instruction or "").strip(),
                "fund_code": str(fund or "").strip().upper(),
                "funds_center_code": str(fc or "").strip().upper(),
                "commitment_item_code": str(ci or "").strip().upper(),
                "amount": None,
                "source_entity_name": str(source_entity_raw or "").strip(),
                "source_biro_code": str(source_biro_raw or "").strip(),
                "allocation_date": dt.isoformat() if hasattr(dt, "isoformat") else str(dt or ""),
                "validation_status": "invalid",
                "validation_message": ""
            }
            if not mapping:
                item["validation_message"] = "Baris tidak terhubung dengan Request ID pada REQUEST_MAP."
            elif item["instruction"] not in ("+", "-"):
                item["validation_message"] = "INSTRUCTION harus berupa + atau -."
            elif not item["commitment_item_code"] or (item["instruction"] == "+" and not item["fund_code"]):
                item["validation_message"] = "COMMITMENT ITEM wajib diisi; FUND wajib untuk instruksi target (+)."
            else:
                try:
                    amount = Decimal(str(amount_raw).replace(",", "").strip())
                    if not amount.is_finite() or amount <= 0 or amount.quantize(Decimal("0.01")) != amount:
                        raise ValueError()
                    item["amount"] = amount
                    item["validation_status"] = "valid"
                except Exception:
                    item["validation_message"] = "AMOUNT harus berupa angka positif dengan maksimal dua desimal."
            parsed_rows.append(item)

        if not parsed_rows:
            return jsonify({"error": "Tidak ada instruksi pada sheet APPROVAL."}), 422

        parsed_request_ids = {row["request_id"] for row in parsed_rows if row["request_id"] is not None}
        missing_instruction_ids = [m["request_id"] for m in mappings if m["request_id"] not in parsed_request_ids]
        if missing_instruction_ids:
            labels = ", ".join(f"REQ-{rid}" for rid in missing_instruction_ids)
            return jsonify({"error": f"REQUEST_MAP memiliki pengajuan tanpa instruksi APPROVAL: {labels}."}), 422

        # Ensure the workbook belongs to the selected batch and each mapped request is a member.
        conn = get_db_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT batch_id FROM public.budget_request_batch WHERE batch_id = %s", (batch_id,))
                if not cur.fetchone():
                    return jsonify({"error": "Batch tidak ditemukan."}), 404

                if any(m["batch_id"] != batch_id for m in mappings):
                    return jsonify({"error": "REQUEST_MAP memuat Batch ID yang berbeda dari batch yang sedang dibuka."}), 422

                cur.execute("""
                    SELECT request_id, batch_id, request_status, budget_id,
                           request_amount, shortage_amount
                    FROM public.budget_request
                    WHERE request_id = ANY(%s)
                """, ([m["request_id"] for m in mappings],))
                reqs = {r["request_id"]: r for r in cur.fetchall()}
                if len(reqs) != len(mappings):
                    return jsonify({"error": "Ada Request ID pada REQUEST_MAP yang tidak ditemukan."}), 422

                for m in mappings:
                    req = reqs[m["request_id"]]
                    if req["batch_id"] != batch_id:
                        return jsonify({"error": f"REQ-{m['request_id']} bukan anggota batch ini."}), 422
                    if req["request_status"] != "Pending":
                        for row in parsed_rows:
                            if row["request_id"] == m["request_id"]:
                                row["validation_status"] = "invalid"
                                row["validation_message"] = f"Status pengajuan bukan Pending (status saat ini: {req['request_status']})."

                # Validate groups by Request ID. One '+' is direct approve candidate;
                # one '+' target plus one or more '-' sources is a reallocation candidate.
                grouped = {}
                for row in parsed_rows:
                    if row["request_id"] is not None:
                        grouped.setdefault(row["request_id"], []).append(row)

                for rid, group in grouped.items():
                    if any(x["validation_status"] != "valid" for x in group):
                        continue
                    plus = [x for x in group if x["instruction"] == "+"]
                    minus = [x for x in group if x["instruction"] == "-"]
                    if len(plus) != 1:
                        msg = "Setiap Request ID harus memiliki tepat satu baris instruksi + sebagai target."
                        for x in group:
                            x["validation_status"], x["validation_message"] = "invalid", msg
                        continue

                    # Target '+' must match the mapped budget of this request.
                    cur.execute("""
                        SELECT f.fund_code, fc.funds_center_code, ci.commitment_item_code
                        FROM public.budget_request br
                        LEFT JOIN public.fund f ON f.fund_id = br.mapped_fund_id
                        LEFT JOIN public.funds_center fc ON fc.funds_center_id = br.mapped_funds_center_id
                        LEFT JOIN public.commitment_item ci ON ci.commitment_item_id = br.mapped_commitment_item_id
                        WHERE br.request_id = %s
                    """, (rid,))
                    target_codes = cur.fetchone()
                    p = plus[0]
                    if not target_codes or (
                        p["fund_code"] != str(target_codes["fund_code"] or "").strip().upper()
                        or (target_codes["funds_center_code"] and
                            p["funds_center_code"] != str(target_codes["funds_center_code"]).strip().upper())
                        or p["commitment_item_code"] != str(target_codes["commitment_item_code"] or "").strip().upper()
                    ):
                        for x in group:
                            x["validation_status"], x["validation_message"] = "invalid", "Instruksi + harus sesuai dengan mapping budget target pengajuan."
                        continue

                    if not minus:
                        # One '+' means approval using automatic Available -> Hold priority.
                        continue

                    if sum(x["amount"] for x in minus) != p["amount"]:
                        for x in group:
                            x["validation_status"], x["validation_message"] = "invalid", "Total instruksi - harus sama dengan instruksi + (nominal realokasi) pada Request ID ini."
                        continue

                    cur.execute("""
                        SELECT bm.budget_id, bm.entity_id, bm.biro_id, bm.budget_year,
                               UPPER(TRIM(bm.budget_scope)) AS budget_scope,
                               bm.funds_center_id, bm.commitment_item_id,
                               bm.available_amount
                        FROM public.budget_master bm
                        WHERE bm.budget_id = %s
                    """, (reqs[rid]["budget_id"],))
                    target_budget = cur.fetchone()
                    if not target_budget:
                        for x in group:
                            x["validation_status"], x["validation_message"] = "invalid", "Budget target pengajuan tidak ditemukan."
                        continue

                    scope = str(target_budget["budget_scope"] or "").strip().upper()
                    # Identifikasi sumber dari informasi bisnis yang diisi Approval,
                    # bukan dari budget_id internal. Kandidat bisa dilihat pada sheet
                    # DONOR_OPTIONS. Pair (unit_entity, biro_code) + scope + CI (+FC)
                    # harus menunjuk SATU budget_master; jangan pilih secara acak.
                    selected_donor_amounts = {}
                    for line in minus:
                        source_entity = line.get("source_entity_name", "").strip().upper()
                        source_biro = " ".join(line.get("source_biro_code", "").split()).upper()
                        if not source_entity or not source_biro:
                            msg = (
                                "Instruksi - wajib mengisi SOURCE ENTITY (kolom F) "
                                "dan SOURCE BIRO (kolom H), sesuai sheet DONOR_OPTIONS."
                            )
                            for x in group:
                                x["validation_status"], x["validation_message"] = "invalid", msg
                            break

                        cur.execute("""
                            SELECT bm.budget_id, bm.available_amount, bm.entity_id,
                                   bm.biro_id, bm.budget_scope, bm.funds_center_id,
                                   fc.funds_center_code, ci.commitment_item_code,
                                   ue.unit_entity, b.biro_code,
                                   hist.fund_code AS historical_fund_code
                            FROM public.budget_master bm
                            JOIN public.commitment_item ci
                              ON ci.commitment_item_id = bm.commitment_item_id
                            JOIN public.unit_entity ue
                              ON ue.entity_id = bm.entity_id
                            JOIN public.biro b
                              ON b.biro_id = bm.biro_id AND b.entity_id = bm.entity_id
                            LEFT JOIN public.funds_center fc
                              ON fc.funds_center_id = bm.funds_center_id
                            LEFT JOIN LATERAL (
                                SELECT f.fund_code
                                FROM public.budget_request old_req
                                JOIN public.fund f ON f.fund_id = old_req.mapped_fund_id
                                WHERE old_req.budget_id = bm.budget_id
                                ORDER BY old_req.request_date DESC, old_req.request_id DESC
                                LIMIT 1
                            ) hist ON TRUE
                            WHERE bm.budget_year = %s
                              AND UPPER(TRIM(bm.budget_scope)) = %s
                              AND bm.commitment_item_id = %s
                              AND (bm.entity_id IS DISTINCT FROM %s
                                   OR bm.biro_id IS DISTINCT FROM %s)
                              AND bm.budget_id <> %s
                              AND (%s <> 'FC_CI' OR bm.funds_center_id = %s)
                              AND UPPER(TRIM(ue.unit_entity)) = %s
                              AND (UPPER(TRIM(b.biro_code)) = %s
                                   OR UPPER(REGEXP_REPLACE(TRIM(b.biro_name), '[[:space:]]+', ' ', 'g')) = %s)
                            ORDER BY bm.budget_id
                        """, (
                            target_budget["budget_year"], scope,
                            target_budget["commitment_item_id"],
                            target_budget["entity_id"], target_budget["biro_id"],
                            reqs[rid]["budget_id"], scope,
                            target_budget["funds_center_id"],
                            source_entity, source_biro, source_biro
                        ))
                        candidates = cur.fetchall() if scope in ("FC_CI", "CI_ONLY") else []
                        if len(candidates) != 1:
                            msg = (
                                f"Sumber {source_entity} / Biro {source_biro} menghasilkan "
                                f"{len(candidates)} budget; harus tepat satu. "
                                "Periksa SOURCE ENTITY, nama/kode SOURCE BIRO, dan kandidat DONOR_OPTIONS."
                            )
                            for x in group:
                                x["validation_status"], x["validation_message"] = "invalid", msg
                            break
                        candidate = candidates[0]
                        # Fund pada baris donor adalah referensi, bukan kunci budget.
                        # Riwayat Fund donor dapat NULL dan tidak boleh menjadi
                        # syarat validasi donor; target (+) tetap divalidasi mappingnya.
                        if scope == "FC_CI" and line["funds_center_code"] != str(candidate["funds_center_code"] or "").strip().upper():
                            msg = "FUNDS CENTER sumber FC_CI tidak sesuai budget donor."
                        elif line["commitment_item_code"] != str(candidate["commitment_item_code"] or "").strip().upper():
                            msg = "COMMITMENT ITEM donor tidak sesuai."
                        else:
                            msg = None
                        if msg:
                            for x in group:
                                x["validation_status"], x["validation_message"] = "invalid", msg
                            break
                        selected_donor_amounts[candidate["budget_id"]] = (
                            selected_donor_amounts.get(candidate["budget_id"], Decimal("0")) + line["amount"]
                        )
                        if selected_donor_amounts[candidate["budget_id"]] > Decimal(str(candidate["available_amount"] or 0)):
                            msg = "Total realokasi dari sumber ini melebihi Available Budget donor."
                            for x in group:
                                x["validation_status"], x["validation_message"] = "invalid", msg
                            break
                        line["source_budget_id"] = candidate["budget_id"]

                    # Nominal realokasi harus tepat sama dengan kekurangan setelah
                    # available sendiri dan approval hold sendiri diprioritaskan.
                    if all(x["validation_status"] == "valid" for x in group):
                        cur.execute("""
                            SELECT current_budget, consumable_budget, available_amount
                            FROM public.budget_master WHERE budget_id = %s
                        """, (reqs[rid]["budget_id"],))
                        live_target = cur.fetchone()
                        shortage = max(Decimal("0"), Decimal(str(reqs[rid]["request_amount"])) - Decimal(str(live_target["available_amount"])))
                        hold = max(Decimal("0"), Decimal(str(live_target["current_budget"])) - Decimal(str(live_target["consumable_budget"])))
                        required = max(Decimal("0"), shortage - hold)
                        if required <= 0 or p["amount"] != required:
                            msg = f"Nominal realokasi harus sama dengan shortage setelah Hold: {required:.2f}."
                            for x in group:
                                x["validation_status"], x["validation_message"] = "invalid", msg


                # Create import batch record. Re-uploading identical bytes returns the existing preview.
                cur.execute("""
                    INSERT INTO public.approval_import_batches
                        (batch_id, uploaded_by, uploaded_filename, file_sha256,
                         import_status, total_rows, valid_rows, invalid_rows, previewed_at)
                    VALUES (%s, %s, %s, %s, 'previewed', %s, %s, %s, NOW())
                    ON CONFLICT (batch_id, file_sha256) DO UPDATE SET
                        uploaded_filename = EXCLUDED.uploaded_filename,
                        import_status = 'previewed',
                        total_rows = EXCLUDED.total_rows,
                        valid_rows = EXCLUDED.valid_rows,
                        invalid_rows = EXCLUDED.invalid_rows,
                        previewed_at = NOW()
                    RETURNING approval_import_id
                """, (
                    batch_id, session["user_id"], filename, digest, len(parsed_rows),
                    sum(x["validation_status"] == "valid" for x in parsed_rows),
                    sum(x["validation_status"] != "valid" for x in parsed_rows)
                ))
                import_id = cur.fetchone()["approval_import_id"]
                cur.execute("DELETE FROM public.approval_import_rows WHERE approval_import_id = %s", (import_id,))
                for row in parsed_rows:
                    # Orphan rows without a Request ID are shown in preview but cannot be staged
                    # because request_id is a required foreign key.
                    if row["request_id"] is None:
                        continue
                    cur.execute("""
                        INSERT INTO public.approval_import_rows
                            (approval_import_id, request_id, excel_row_number, instruction,
                             fund_code, funds_center_code, commitment_item_code, amount,
                             validation_status, validation_message, source_budget_id)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        import_id, row["request_id"], row["excel_row_number"], row["instruction"],
                        row["fund_code"] or None, row["funds_center_code"], row["commitment_item_code"],
                        row["amount"] if row["amount"] is not None else Decimal("0.01"),
                        row["validation_status"], row["validation_message"], row.get("source_budget_id")
                    ))

        return jsonify({
            "success": True, "approval_import_id": import_id, "batch_id": batch_id,
            "filename": filename, "total": len(parsed_rows),
            "valid": sum(x["validation_status"] == "valid" for x in parsed_rows),
            "invalid": sum(x["validation_status"] != "valid" for x in parsed_rows),
            "rows": [{
                **{k: (str(v) if isinstance(v, Decimal) else v) for k, v in x.items() if k not in ("source_budget_id", "donor_budget_id")},
                "request_label": f"REQ-{x['request_id']}" if x["request_id"] else "—"
            } for x in parsed_rows]
        })
    except (ValueError, KeyError, InvalidOperation):
        app.logger.exception("Format Excel Approval tidak valid")
        return jsonify({"error": "Format Excel Approval tidak valid. Periksa kembali template."}), 422
    except psycopg2.Error:
        app.logger.exception("Gagal menyimpan preview Excel Approval")
        return jsonify({"error": "Gagal menyimpan preview ke database. Periksa log aplikasi."}), 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/api/approval/batches/<int:batch_id>/confirm/<int:import_id>", methods=["POST"])
def api_approval_excel_confirm(batch_id, import_id):
    guard=approval_mutation_guard()
    if guard is not None: return guard
    conn=None
    try:
        conn=get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute('''SELECT approval_import_id,import_status FROM public.approval_import_batches
                WHERE approval_import_id=%s AND batch_id=%s''',(import_id,batch_id))
            imp=cur.fetchone()
            if not imp: return jsonify({'error':'Preview import tidak ditemukan.'}),404
            if imp['import_status'] not in ('previewed','partially_processed'):
                return jsonify({'error':'File sudah diproses atau tidak dapat diproses ulang.'}),409
            cur.execute('''SELECT request_id,instruction,fund_code,funds_center_code,
                           commitment_item_code,amount,source_budget_id,validation_status
                           FROM public.approval_import_rows WHERE approval_import_id=%s
                           ORDER BY request_id,excel_row_number''',(import_id,))
            staged=cur.fetchall()
        conn.close();conn=None
        grouped={}
        for line in staged: grouped.setdefault(line['request_id'],[]).append(line)
        results=[]
        for rid,lines in grouped.items():
            if any(x['validation_status']!='valid' for x in lines):
                results.append({'request_id':rid,'status':'invalid',
                                'message':'Seluruh instruksi dibatalkan karena ada baris invalid.'})
                continue
            plus=[x for x in lines if x['instruction']=='+']
            minus=[x for x in lines if x['instruction']=='-']
            if len(plus)!=1:
                results.append({'request_id':rid,'status':'invalid','message':'Harus ada tepat satu baris +.'})
                continue
            per_conn=None
            try:
                allocs=[]
                for x in minus:
                    if x['source_budget_id'] is None: raise ApprovalEngineError('Donor belum tervalidasi.')
                    allocs.append({'source_budget_id':int(x['source_budget_id']),
                                   'amount':x['amount'],'allocation_date':date.today(),
                                   'instruction':f'Excel Approval Import {import_id}',
                                   'fund_code':x['fund_code'],
                                   'funds_center_code':x['funds_center_code'],
                                   'commitment_item_code':x['commitment_item_code']})
                per_conn=get_db_connection()
                with per_conn:
                    with per_conn.cursor(cursor_factory=RealDictCursor) as cur:
                        result=execute_approval(cur,session['user_id'],rid,
                            'reallocate' if allocs else 'auto',
                            allocations=allocs,instruction=f'Excel Approval Import {import_id}',
                            expected_batch_id=batch_id)
                msg=result['message']
                if result['approval_decision']=='Approve':
                    msg='1 pengajuan berhasil disetujui dalam satu Batch Approval.'
                results.append({'request_id':rid,'status':'processed','message':msg})
            except (ApprovalEngineError,ValueError,psycopg2.Error) as exc:
                if per_conn: per_conn.rollback()
                if isinstance(exc,psycopg2.Error):
                    app.logger.exception('Excel confirm gagal untuk REQ-%s',rid)
                    msg='Terjadi kesalahan database saat konfirmasi.'
                else: msg=str(exc)
                results.append({'request_id':rid,'status':'invalid','message':msg})
            finally:
                if per_conn: per_conn.close()
        conn=get_db_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Prevent replay of the same import result.
                cur.execute('''SELECT import_status FROM public.approval_import_batches
                    WHERE approval_import_id=%s AND batch_id=%s FOR UPDATE''',(import_id,batch_id))
                current=cur.fetchone()
                if not current or current['import_status'] not in ('previewed','partially_processed'):
                    raise ApprovalEngineError('Preview sudah diproses oleh proses lain.')
                for result in results:
                    cur.execute('''UPDATE public.approval_import_rows
                        SET validation_status=%s,validation_message=%s
                        WHERE approval_import_id=%s AND request_id=%s''',
                        ('processed' if result['status']=='processed' else 'invalid',
                         result['message'],import_id,result['request_id']))
                processed=sum(x['status']=='processed' for x in results)
                failed=len(results)-processed
                state='completed' if failed==0 else ('partially_processed' if processed else 'failed')
                cur.execute('''UPDATE public.approval_import_batches
                    SET import_status=%s,confirmed_at=NOW(),
                    completed_at=CASE WHEN %s IN ('completed','partially_processed')
                      THEN NOW() ELSE completed_at END
                    WHERE approval_import_id=%s''',(state,state,import_id))
        return jsonify({'success':processed>0,'processed':processed,'failed':failed,'results':results})
    except (ApprovalEngineError,ValueError) as exc:
        if conn: conn.rollback()
        return jsonify({'error':str(exc)}),409
    except psycopg2.Error:
        if conn: conn.rollback()
        app.logger.exception('Konfirmasi Excel gagal')
        return jsonify({'error':'Pemrosesan gagal. Periksa log aplikasi.'}),500
    finally:
        if conn: conn.close()




def _budget_export_file(user_mode=False, request_id=None, batch_id=None):
    """
    Export template budget untuk sisi Approval.
    Kedua sheet selalu mengikuti filter request yang sama:
    - APPROVEL: realokasi/keputusan aktual, atau rancangan (+) untuk Pending.
    - USER: data pengajuan dari pengusul.
    """
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            where = []
            params = []

            # Endpoint ini dipakai Approval. Filter user_mode tetap dipertahankan
            # agar helper kompatibel jika kelak dipakai sisi Pengusul.
            if user_mode:
                where.append("br.user_id = %s")
                params.append(session["user_id"])
            if request_id is not None:
                where.append("br.request_id = %s")
                params.append(request_id)
            if batch_id is not None:
                where.append("br.batch_id = %s")
                params.append(batch_id)

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

            # Kandidat donor aktual berdasarkan prioritas scope pada PDF.
            # Hanya menampilkan kode bisnis, bukan budget_id internal.
            donor_options = []
            for r in requests_data:
                if str(r["request_status"] or "").lower() != "pending":
                    continue
                cursor.execute("""
                    SELECT d.budget_scope, ue.unit_entity, b.biro_code, b.biro_name,
                           fc.funds_center_code, ci.commitment_item_code,
                           d.available_amount, source_fund_ref.fund_code AS fund_reference
                    FROM public.budget_request br
                    JOIN public.budget_master target ON target.budget_id = br.budget_id
                    JOIN public.budget_master d
                      ON d.budget_year = target.budget_year
                     AND d.budget_scope = target.budget_scope
                     AND d.commitment_item_id = target.commitment_item_id
                     AND d.budget_id <> target.budget_id
                     AND (d.entity_id IS DISTINCT FROM target.entity_id
                          OR d.biro_id IS DISTINCT FROM target.biro_id)
                     AND (target.budget_scope <> 'FC_CI'
                          OR d.funds_center_id = target.funds_center_id)
                     JOIN public.unit_entity ue ON ue.entity_id = d.entity_id
                    JOIN public.biro b ON b.biro_id = d.biro_id AND b.entity_id = d.entity_id
                    JOIN public.commitment_item ci ON ci.commitment_item_id = d.commitment_item_id
                    LEFT JOIN public.funds_center fc ON fc.funds_center_id = d.funds_center_id
                    LEFT JOIN LATERAL (
                        SELECT f.fund_code FROM public.budget_request older
                        JOIN public.fund f ON f.fund_id = older.mapped_fund_id
                        WHERE older.budget_id = d.budget_id
                        ORDER BY older.request_date DESC, older.request_id DESC LIMIT 1
                    ) source_fund_ref ON TRUE
                    WHERE br.request_id = %s AND d.available_amount > 0
                    ORDER BY d.available_amount DESC, ue.unit_entity, b.biro_code
                """, (r["request_id"],))
                for row in cursor.fetchall():
                    donor_options.append((r["request_id"], row))

        wb = Workbook()
        ws_a = wb.active
        ws_a.title = "APPROVAL"
        ws_u = wb.create_sheet("USER")
        ws_map = wb.create_sheet("REQUEST_MAP")
        ws_donor = wb.create_sheet("DONOR_OPTIONS")
        ws_donor.append(["REQUEST ID", "BUDGET SCOPE", "SOURCE ENTITY", "SOURCE BIRO", "BIRO CODE", "FUNDS CENTER", "COMMITMENT ITEM", "AVAILABLE", "FUND REFERENSI"])
        for rid, candidate in donor_options:
            ws_donor.append([rid, candidate["budget_scope"], candidate["unit_entity"],
                             candidate["biro_name"], candidate["biro_code"],
                             candidate["funds_center_code"], candidate["commitment_item_code"],
                             float(candidate["available_amount"] or 0), candidate["fund_reference"]])
        ws_donor.freeze_panes = "A2"
        ws_donor.auto_filter.ref = f"A1:I{ws_donor.max_row}"
        for idx, width in enumerate([16, 18, 28, 36, 18, 22, 24, 20, 20], 1):
            ws_donor.column_dimensions[get_column_letter(idx)].width = width
        for cell in ws_donor[1]:
            cell.font = Font(color="FFFFFF", bold=True)
            cell.fill = PatternFill("solid", fgColor="ED1C24")
        for rno in range(2, ws_donor.max_row + 1):
            ws_donor.cell(rno, 1).number_format = "0"
            ws_donor.cell(rno, 8).number_format = '#,##0.00'


        # Header dan urutan kolom dipertahankan sesuai template 10 November.
        ws_a.append(["BUDGET"])
        ws_a.append([
            "DATE", "INSTRUCTION", "FUND", "FUNDS CENTER",
            "COMMITMENT ITEM", "SOURCE ENTITY", "AMOUNT", "SOURCE BIRO"
        ])
        ws_a.append([
            "(TANGGAL)", "(+/-) OPSIONAL", "(LINK COSTCENTER)",
            "(LINK COSTCENTER)", "(LINK G/L)", "(ENTITY DONOR UNTUK -)", "(NOMINAL)", "(BIRO DONOR UNTUK -)"
        ])

        ws_u.append([None, "DATABASE"])
        ws_u.append([
            "DATE", "PIC", "PROFIT CENTER", "COST CENTER",
            "GL ACCOUNT", "AMOUNT", "KETERANGAN"
        ])
        ws_u.append([
            "(TANGGAL)", "(NAMA)", "(PROFIT CENTER)", "(COST CENTER)",
            "(KODE GL)", "(NOMINAL)", "(KETERANGAN PENGAJUAN)"
        ])

        # USER: satu baris untuk setiap pengajuan yang masuk dalam cakupan export.
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

        # REQUEST_MAP menghubungkan setiap Request ID dengan baris APPROVAL.
        ws_map.append(["REQUEST ID", "BATCH ID", "STATUS", "APPROVAL ROW START", "APPROVAL ROW END"])

        # APPROVAL: setiap pengajuan mendapat baris sesuai keadaan pengajuannya.
        for r in requests_data:
            approval_row_start = ws_a.max_row + 1
            rid = r["request_id"]
            request_allocations = allocations_by_request.get(rid, [])
            request_decisions = decisions_by_request.get(rid, [])
            status = str(r["request_status"] or "").strip().lower()
            request_date = r["transaction_date"] or r["request_date"]

            if request_allocations:
                # Ini ekspor referensi historis, BUKAN template untuk re-upload.
                # Open Budget berasal dari Approval Hold target, BUKAN donor (-).
                # Reallocation menghasilkan baris (-) donor dan (+) target.
                opened_lines = [a for a in request_allocations
                                if a["allocation_type"] == "Open Budget"]
                donor_lines = [a for a in request_allocations
                               if a["allocation_type"] in (
                                   "Reallocation FC_CI", "Reallocation CI_Only")]
                for a in opened_lines:
                    row_idx = ws_a.max_row + 1
                    ws_a.append([
                        a["allocation_date"] or request_date, "+",
                        a["target_fund"] or r["fund_code"],
                        a["target_fc"] or r["funds_center_code"],
                        a["target_ci"] or r["commitment_item_code"],
                        None, float(a["amount"] or 0)
                    ])
                    ws_a.cell(row_idx, 7).comment = Comment(
                        "Open Budget dari Approval Hold; bukan total Approved Amount.",
                        "SILOG Budget Monitoring"
                    )
                if donor_lines:
                    total_reallocation = sum(
                        (Decimal(str(a["amount"] or 0)) for a in donor_lines),
                        Decimal("0")
                    )
                    for a in donor_lines:
                        ws_a.append([
                            a["allocation_date"] or request_date, "-",
                            a["source_fund"], a["source_fc"],
                            a["source_ci"], None, float(a["amount"] or 0)
                        ])
                    first = donor_lines[0]
                    ws_a.append([
                        first["allocation_date"] or request_date, "+",
                        first["target_fund"] or r["fund_code"],
                        first["target_fc"] or r["funds_center_code"],
                        first["target_ci"] or r["commitment_item_code"],
                        None, float(total_reallocation)
                    ])
                ws_map.append([rid, batch_id if batch_id is not None else None,
                               r["request_status"], approval_row_start, ws_a.max_row])
                continue

            # Tanpa alokasi, nilai Approved Amount bisnis = total pengajuan.
            # Jangan gunakan approved_amount mentah pada histori lama.
            if request_decisions:
                for d in request_decisions:
                    decision = str(d["decision"] or "").strip().lower()
                    if "reject" in decision:
                        continue
                    if "approve" in decision or "open budget" in decision:
                        row_idx = ws_a.max_row + 1
                        ws_a.append([
                            d["decision_date"].date() if d["decision_date"] else request_date,
                            "+",
                            d["fund_code"] or r["fund_code"],
                            d["funds_center_code"] or r["funds_center_code"],
                            d["commitment_item_code"] or r["commitment_item_code"],
                            None,
                            float(r["request_amount"] or 0)
                        ])
                ws_map.append([rid, batch_id if batch_id is not None else None, r["request_status"], approval_row_start, ws_a.max_row])
                continue

            # Pending: tampilkan rancangan penambahan (+), bukan transaksi aktual.
            if "pending" in status:
                row_idx = ws_a.max_row + 1
                ws_a.append([
                    request_date,
                    "+",
                    r["fund_code"],
                    r["funds_center_code"],
                    r["commitment_item_code"],
                    None,
                    float(r["request_amount"] or 0)
                ])
                # Beri penanda eksplisit tanpa mengubah nama/urutan kolom template.
                ws_a.cell(row=row_idx, column=2).comment = Comment(
                    "RANCANGAN PENGAJUAN PENDING — belum merupakan keputusan "
                    "Approval atau transaksi perubahan budget.",
                    "SILOG Budget Monitoring"
                )
                ws_a.cell(row=row_idx, column=7).comment = Comment(
                    "Nominal ini merupakan nominal pengajuan dari Pengusul, "
                    "bukan nominal yang sudah disetujui.",
                    "SILOG Budget Monitoring"
                )
            ws_map.append([rid, batch_id if batch_id is not None else None, r["request_status"], approval_row_start, ws_a.max_row])

        # Request ID must remain numeric; never inherit date formatting.
        for map_row in range(2, ws_map.max_row + 1):
            ws_map.cell(row=map_row, column=1).number_format = "0"
            ws_map.cell(row=map_row, column=2).number_format = "0"
            ws_map.cell(row=map_row, column=4).number_format = "0"
            ws_map.cell(row=map_row, column=5).number_format = "0"

        # Petunjuk menjelaskan format input dan relasi antar-sheet.
        ws_help = wb.create_sheet("PETUNJUK")
        instructions = [
            ["PETUNJUK PENGGUNAAN TEMPLATE APPROVAL SILOG"],
            ["1. APPROVAL", "Isi/ubah instruksi dengan tanda + untuk penambahan atau - untuk pengurangan anggaran. Satu baris mewakili satu instruksi budget."],
            ["2. Kolom DATE", "Gunakan tanggal transaksi dengan format tanggal Excel."],
            ["3. Kolom FUND / FUNDS CENTER / COMMITMENT ITEM", "Gunakan kode yang sesuai master data SILOG."],
            ["3a. Sumber realokasi", "Untuk instruksi (-), isi SOURCE ENTITY (kolom F) dan NAMA SOURCE BIRO (kolom H) dari sheet DONOR_OPTIONS. FUND donor boleh kosong bila referensinya tidak tersedia; untuk (+), FUND hasil mapping pengajuan wajib terisi."],
            ["3b. DONOR_OPTIONS", "Berisi donor sesuai Scope, CI, serta FC jika FC_CI. Salin SOURCE ENTITY + nama SOURCE BIRO. FUND REFERENSI hanya informasi historis, bukan kunci donor. Saldo diperiksa ulang saat konfirmasi."],
            ["4. Kolom AMOUNT", "Isi nominal positif. Arah transaksi ditentukan oleh INSTRUCTION (+/-)."],
            ["5. USER", "Berisi data asal pengajuan dari Pengusul sebagai referensi. Jangan mengubah data sumber."],
            ["6. REQUEST_MAP", "Menghubungkan Request ID dengan rentang baris terkait pada sheet APPROVAL. Gunakan untuk mengetahui pengajuan mana yang dirujuk."],
            ["7. Catatan", "Template ini merupakan lembar kerja referensi untuk satu batch. Upload/konfirmasi keputusan tetap mengikuti validasi SILOG."],
            ["8. Histori Alokasi", "Baris + Open Budget menunjukkan pembukaan Hold; baris -/+ Reallocation menunjukkan perpindahan dana. Total Approved Amount adalah Request Amount di sheet USER, bukan penjumlahan seluruh baris +."],
        ]
        for row in instructions:
            ws_help.append(row)
        ws_help.column_dimensions["A"].width = 34
        ws_help.column_dimensions["B"].width = 110
        ws_help.freeze_panes = "A2"
        ws_help["A1"].font = Font(bold=True, color="FFFFFF", size=14)
        ws_help["A1"].fill = PatternFill("solid", fgColor="ED1C24")
        ws_help.merge_cells("A1:B1")
        for row in ws_help.iter_rows(min_row=2):
            row[0].font = Font(bold=True, color="30394B")
            row[0].alignment = Alignment(vertical="top", wrap_text=True)
            row[1].alignment = Alignment(vertical="top", wrap_text=True)
            ws_help.row_dimensions[row[0].row].height = 34

        # Format visual mengikuti template dan tidak menambah kolom baru.
        header_fill = PatternFill("solid", fgColor="ED1C24")
        white_bold = Font(color="FFFFFF", bold=True)
        thin = Side(style="thin", color="D9DEE7")

        for ws, header_row, widths in [
            (ws_a, 2, [16, 16, 20, 22, 24, 28, 20, 18]),
            (ws_u, 2, [16, 22, 20, 22, 20, 20, 48]),
            (ws_map, 1, [18, 14, 18, 22, 22])
        ]:
            ws.freeze_panes = f"A{header_row + 1}"
            ws.auto_filter.ref = (
                f"A{header_row}:{get_column_letter(ws.max_column)}{ws.max_row}"
            )
            for cell in ws[header_row]:
                cell.fill = header_fill
                cell.font = white_bold
                cell.alignment = Alignment(
                    horizontal="center", vertical="center"
                )
            for col, width in enumerate(widths, start=1):
                ws.column_dimensions[get_column_letter(col)].width = width
            for row in ws.iter_rows(min_row=header_row + 1):
                for cell in row:
                    cell.border = Border(bottom=thin)
                    if cell.column == 1 and ws.title != "REQUEST_MAP":
                        cell.number_format = "dd/mm/yyyy"
                    if (
                        (ws.title == "APPROVAL" and cell.column == 7)
                        or (ws.title == "USER" and cell.column == 6)
                    ):
                        cell.number_format = '#,##0.00'
            ws.row_dimensions[header_row].height = 24

        output = BytesIO()
        wb.save(output)
        output.seek(0)

        suffix = (f"_REQ_{request_id}" if request_id is not None else
                  f"_BATCH_{batch_id}" if batch_id is not None else "_SEMUA")
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



# ============================================================
# EXPORT RIWAYAT APPROVAL - LAPORAN AUDIT (READ ONLY)
# Mengikuti filter Riwayat Approval tanpa pembatasan pagination.
# Tidak mengubah transaksi, status, atau budget_master.
# ============================================================
@app.route("/approval/export-history.xlsx", methods=["GET"])
def export_approval_history_audit():
    guard = approval_api_guard()
    if guard is not None:
        return guard

    kind = request.args.get("kind", "ALL").strip().upper()
    status = request.args.get("status", "ALL").strip()
    keyword = request.args.get("q", "").strip()
    if kind not in {"ALL", "SATUAN", "BATCH"}:
        return jsonify({"error": "Jenis pengajuan tidak valid."}), 400
    if status not in {"ALL", "Approved", "Rejected"}:
        return jsonify({"error": "Status pengajuan tidak valid."}), 400
    if len(keyword) > 150:
        return jsonify({"error": "Pencarian terlalu panjang."}), 400

    where = ["br.request_status IN ('Approved','Rejected')"]
    params = []
    if kind == "SATUAN":
        where.append("br.batch_id IS NULL")
    elif kind == "BATCH":
        where.append("br.batch_id IS NOT NULL")
    if status != "ALL":
        where.append("br.request_status = %s")
        params.append(status)
    if keyword:
        where.append("""(
            CAST(br.request_id AS TEXT) ILIKE %s
            OR COALESCE(br.pic,'') ILIKE %s
            OR COALESCE(br.request_description,'') ILIKE %s
            OR COALESCE(u.username,'') ILIKE %s
            OR COALESCE(bb.batch_code,'') ILIKE %s
        )""")
        params.extend([f"%{keyword}%"] * 5)
    where_sql = " AND ".join(where)

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Query sama dengan API /api/approval/history untuk memastikan
            # filter dan urutan ekspor cocok dengan tabel pada website.
            cur.execute(f"""
                SELECT br.request_id, br.batch_id, bb.batch_code,
                       bb.uploaded_filename, br.request_date, br.pic,
                       br.request_amount, br.request_description,
                       br.request_status, br.budget_status,
                       br.budget_id, br.budget_scope,
                       u.username AS requester_username,
                       ue.unit_entity,
                       COALESCE(b.biro_name, budget_biro.biro_name) AS biro_name,
                       ci.commitment_item_code, ci.commitment_item_name,
                       latest_decision.decision AS approval_decision,
                       latest_decision.decision_date,
                       latest_decision.instruction AS approval_instruction,
                       latest_decision.approved_amount,
                       approver.username AS approval_username
                FROM public.budget_request br
                JOIN public.users u ON u.user_id = br.user_id
                LEFT JOIN public.budget_request_batch bb ON bb.batch_id = br.batch_id
                LEFT JOIN public.unit_entity ue ON ue.entity_id = br.entity_id
                LEFT JOIN public.biro b ON b.biro_id = u.biro_id AND b.entity_id = br.entity_id
                LEFT JOIN public.budget_master audit_bm ON audit_bm.budget_id = br.budget_id
                LEFT JOIN public.biro budget_biro ON budget_biro.biro_id = audit_bm.biro_id
                    AND budget_biro.entity_id = audit_bm.entity_id
                LEFT JOIN public.commitment_item ci ON ci.commitment_item_id = br.mapped_commitment_item_id
                LEFT JOIN LATERAL (
                    SELECT ad.decision, ad.decision_date, ad.instruction,
                           ad.approved_amount, ad.approval_user_id
                    FROM public.approval_decision ad
                    WHERE ad.request_id = br.request_id
                    ORDER BY ad.decision_date DESC, ad.approval_id DESC
                    LIMIT 1
                ) latest_decision ON TRUE
                LEFT JOIN public.users approver ON approver.user_id = latest_decision.approval_user_id
                WHERE {where_sql}
                ORDER BY COALESCE(latest_decision.decision_date, br.request_date) DESC,
                         br.request_id DESC
            """, params)
            rows = cur.fetchall()
            ids = [int(row["request_id"]) for row in rows]
            allocations = []
            mutations = []
            if ids:
                cur.execute("""
                    SELECT ba.allocation_id, ba.request_id, ba.allocation_type,
                           ba.source_budget_id, ba.target_budget_id,
                           ba.amount, ba.instruction, maker.username AS approved_by,
                           src_ue.unit_entity AS source_entity, src_b.biro_name AS source_biro,
                           dst_ue.unit_entity AS target_entity, dst_b.biro_name AS target_biro
                    FROM public.budget_allocation ba
                    LEFT JOIN public.users maker ON maker.user_id = ba.approved_by
                    LEFT JOIN public.budget_master src ON src.budget_id = ba.source_budget_id
                    LEFT JOIN public.unit_entity src_ue ON src_ue.entity_id = src.entity_id
                    LEFT JOIN public.biro src_b ON src_b.biro_id = src.biro_id AND src_b.entity_id = src.entity_id
                    LEFT JOIN public.budget_master dst ON dst.budget_id = ba.target_budget_id
                    LEFT JOIN public.unit_entity dst_ue ON dst_ue.entity_id = dst.entity_id
                    LEFT JOIN public.biro dst_b ON dst_b.biro_id = dst.biro_id AND dst_b.entity_id = dst.entity_id
                    WHERE ba.request_id = ANY(%s)
                    ORDER BY ba.request_id, ba.allocation_id
                """, (ids,))
                allocations = cur.fetchall()
                cur.execute("""
                    SELECT bh.history_id, bh.request_id, bh.transaction_date,
                           bh.budget_id, bh.action, bh.field_name,
                           bh.previous_value, bh.updated_value, bh.amount,
                           actor.username AS created_by
                    FROM public.budget_history bh
                    LEFT JOIN public.users actor ON actor.user_id = bh.created_by
                    WHERE bh.request_id = ANY(%s)
                    ORDER BY bh.transaction_date, bh.history_id
                """, (ids,))
                mutations = cur.fetchall()

        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        from openpyxl.utils import get_column_letter
        from zoneinfo import ZoneInfo
        from datetime import timezone

        jakarta = ZoneInfo("Asia/Jakarta")
        def local_dt(value):
            if value is None:
                return None
            if isinstance(value, datetime):
                if value.tzinfo is None:
                    value = value.replace(tzinfo=timezone.utc)
                return value.astimezone(jakarta).replace(tzinfo=None)
            return value

        # Supaya nilai yang diawali = + - @ tidak ditafsir Excel sebagai formula.
        def safe_cell(value):
            if value is None:
                return None
            if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
                return "'" + value
            return value

        wb = Workbook()
        ws_history = wb.active
        ws_history.title = "Riwayat Approval"
        ws_allocation = wb.create_sheet("Detail Alokasi")
        ws_mutation = wb.create_sheet("Mutasi Budget")

        def render_sheet(ws, title, headers, records, widths, money_cols=(), date_cols=()):
            ncol = len(headers)
            ws.sheet_view.showGridLines = False
            ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=ncol)
            c = ws.cell(1, 1, title)
            c.font = Font(name="Aptos", size=15, bold=True, color="FFFFFF")
            c.fill = PatternFill("solid", fgColor="B51228")
            c.alignment = Alignment(vertical="center")
            ws.row_dimensions[1].height = 33
            ws.merge_cells(start_row=2, start_column=1, end_row=2, end_column=ncol)
            ws.cell(2, 1, f"Jenis: {kind} | Status: {status} | Pencarian: {keyword or 'Semua'} | Ekspor: {datetime.now(jakarta):%d/%m/%Y %H:%M} WIB")
            ws.cell(2, 1).font = Font(size=10, italic=True, color="566273")
            ws.row_dimensions[2].height = 26
            for j, name in enumerate(headers, 1):
                cell = ws.cell(4, j, name)
                cell.fill = PatternFill("solid", fgColor="263345")
                cell.font = Font(color="FFFFFF", bold=True, size=10)
                cell.alignment = Alignment(vertical="center", wrap_text=True)
            ws.row_dimensions[4].height = 30
            for i, record in enumerate(records, 5):
                for j, value in enumerate(record, 1):
                    cell = ws.cell(i, j, safe_cell(value))
                    cell.font = Font(name="Aptos", size=10, color="243043")
                    cell.alignment = Alignment(vertical="center", wrap_text=False)
                    if i % 2 == 0:
                        cell.fill = PatternFill("solid", fgColor="F2F5F8")
                    if j in money_cols and value is not None:
                        cell.number_format = '"Rp" #,##0.00;[Red]("Rp" #,##0.00)'
                    if j in date_cols and value is not None:
                        cell.number_format = "dd/mm/yyyy hh:mm"
            for j, width in enumerate(widths, 1):
                ws.column_dimensions[get_column_letter(j)].width = width
            ws.freeze_panes = "A5"
            last_row = max(5, 4 + len(records))
            ws.auto_filter.ref = f"A4:{get_column_letter(ncol)}{last_row}"
            ws.sheet_properties.pageSetUpPr.fitToPage = True
            ws.print_options.horizontalCentered = True
            ws.sheet_properties.outlinePr.summaryBelow = True
            ws.sheet_view.zoomScale = 90

        render_sheet(ws_history, "LAPORAN RIWAYAT APPROVAL — SILOG", [
            "Request ID", "Tanggal Pengajuan (WIB)", "Tanggal Keputusan (WIB)",
            "Jenis Pengajuan", "Kode Batch", "Nama File Excel", "Pengusul", "PIC",
            "Unit Entity", "Biro", "Commitment Item", "Nama Commitment Item",
            "Budget ID", "Budget Scope", "Nominal Pengajuan (Rp)",
            "Nominal Disetujui (Rp)", "Keputusan", "Status", "Approver", "Instruksi / Catatan"
        ], [(
            f"REQ-{r['request_id']}", local_dt(r['request_date']), local_dt(r['decision_date']),
            "Excel" if r['batch_id'] is not None else "Satuan", r['batch_code'], r['uploaded_filename'],
            r['requester_username'], r['pic'], r['unit_entity'], r['biro_name'],
            r['commitment_item_code'], r['commitment_item_name'], r['budget_id'], r['budget_scope'],
            r['request_amount'], (r['request_amount'] if r['request_status'] == 'Approved' else Decimal('0')), r['approval_decision'],
            r['request_status'], r['approval_username'], r['approval_instruction']
        ) for r in rows], [16,23,24,17,27,30,20,22,25,23,20,31,14,15,23,23,26,15,20,44],
        money_cols=(15,16), date_cols=(2,3))

        render_sheet(ws_allocation, "DETAIL ALOKASI — SILOG", [
            "Request ID", "Allocation ID", "Jenis Alokasi", "Budget Donor ID", "Entity Donor",
            "Biro Donor", "Budget Tujuan ID", "Entity Tujuan", "Biro Tujuan",
            "Nominal (Rp)", "Disetujui Oleh", "Catatan Alokasi"
        ], [(
            f"REQ-{r['request_id']}", r['allocation_id'], r['allocation_type'],
            r['source_budget_id'], r['source_entity'], r['source_biro'],
            r['target_budget_id'], r['target_entity'], r['target_biro'],
            r['amount'], r['approved_by'], r['instruction']
        ) for r in allocations], [16,17,25,20,27,24,21,27,24,23,21,45], money_cols=(10,))

        render_sheet(ws_mutation, "MUTASI BUDGET — SILOG", [
            "Request ID", "History ID", "Tanggal Mutasi (WIB)", "Budget ID", "Action",
            "Field", "Nilai Sebelum (Rp)", "Nilai Sesudah (Rp)",
            "Nominal Mutasi (Rp)", "Diproses Oleh"
        ], [(
            f"REQ-{r['request_id']}", r['history_id'], local_dt(r['transaction_date']),
            r['budget_id'], r['action'], r['field_name'], r['previous_value'],
            r['updated_value'], r['amount'], r['created_by']
        ) for r in mutations], [16,16,24,17,23,25,23,23,24,23],
        money_cols=(7,8,9), date_cols=(3,))

        # Ringkasan finansial per Request ID tanpa penggandaan field history.
        # Perubahan dihitung hanya dari field yang menjadi tolok ukur nominal:
        # consumable_budget untuk Open; current_budget untuk Reallocation In;
        # consumed_budget untuk Consume. Donor dicatat terpisah dari target.
        ws_summary = wb.create_sheet("Ringkasan Finansial", 1)
        by_request = {}
        for entry in mutations:
            rid = int(entry['request_id'])
            item = by_request.setdefault(rid, {
                'opened': Decimal('0'), 'reallocation_in': Decimal('0'),
                'reallocation_out': Decimal('0'), 'consumed': Decimal('0')
            })
            delta = Decimal(str(entry['updated_value'] or 0)) - Decimal(str(entry['previous_value'] or 0))
            if entry['action'] == 'Open Budget' and entry['field_name'] == 'consumable_budget':
                item['opened'] += delta
            elif entry['action'] == 'Reallocation In' and entry['field_name'] == 'current_budget':
                item['reallocation_in'] += delta
            elif entry['action'] == 'Reallocation Out' and entry['field_name'] == 'current_budget':
                item['reallocation_out'] -= delta
            elif entry['action'] == 'Consume Budget' and entry['field_name'] == 'consumed_budget':
                item['consumed'] += delta
        summary_rows = []
        for r in rows:
            rid = int(r['request_id'])
            item = by_request.get(rid, {})
            opened = item.get('opened', Decimal('0'))
            incoming = item.get('reallocation_in', Decimal('0'))
            outgoing = item.get('reallocation_out', Decimal('0'))
            consumed = item.get('consumed', Decimal('0'))
            approved = Decimal(str(r['request_amount'])) if r['request_status'] == 'Approved' else Decimal('0')
            summary_rows.append((
                f"REQ-{rid}", local_dt(r['decision_date']), r['budget_scope'],
                r['unit_entity'], r['biro_name'], r['budget_id'],
                r['request_amount'], approved, r['approval_decision'],
                opened, incoming, outgoing, consumed,
                'OK' if r['request_status'] == 'Approved'
                    and consumed == approved and incoming == outgoing else
                ('DITOLAK' if r['request_status'] == 'Rejected' else 'PERIKSA'),
                'Perhitungan dari histori field spesifik; bukan penjumlahan semua mutasi'
            ))
        render_sheet(ws_summary, "RINGKASAN FINANSIAL PER REQUEST — SILOG", [
            "Request ID", "Tanggal Keputusan (WIB)", "Budget Scope",
            "Unit Entity", "Biro", "Budget ID", "Nominal Pengajuan (Rp)",
            "Nominal Disetujui (Rp)", "Keputusan", "Open Budget (Rp)",
            "Reallocation In (Rp)", "Reallocation Out (Rp)",
            "Consume Budget (Rp)", "Rekonsiliasi", "Catatan Metode"
        ], summary_rows, [16,24,15,25,33,14,23,23,28,21,23,23,23,17,67],
            money_cols=(7,8,10,11,12,13), date_cols=(2,))

        output = BytesIO()
        wb.save(output)
        output.seek(0)
        return send_file(output, as_attachment=True,
                         download_name=f"SILOG_Riwayat_Approval_{datetime.now(jakarta):%Y%m%d_%H%M}.xlsx",
                         mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    except psycopg2.Error:
        app.logger.exception("Gagal mengekspor audit riwayat Approval")
        return jsonify({"error": "Laporan Riwayat Approval gagal dibuat."}), 500
    finally:
        if conn is not None:
            conn.close()




# ============================================================
# EXPORT RIWAYAT APPROVAL - FORMAT APPROVAL / USER (READ ONLY)
# Dua sheet sesuai format operasional, terpisah dari laporan audit.
# Tidak digunakan sebagai template upload approval: tidak memuat
# REQUEST_MAP atau metadata validasi untuk memproses keputusan.
# ============================================================
@app.route("/approval/export-history-format.xlsx", methods=["GET"])
def export_approval_history_format():
    """Read-only export of stored input, never synthetic approval instructions.

    APPROVAL reflects rows from *processed* Excel approval imports only.
    A row which is missing in the archive is shown as unavailable, NOT
    reconstructed from the request amount or from allocation records.
    """
    guard = approval_api_guard()
    if guard is not None:
        return guard

    kind = request.args.get("kind", "ALL").strip().upper()
    status = request.args.get("status", "ALL").strip()
    keyword = request.args.get("q", "").strip()
    if kind not in {"ALL", "SATUAN", "BATCH"}:
        return jsonify({"error": "Jenis pengajuan tidak valid."}), 400
    if status not in {"ALL", "Approved", "Rejected"}:
        return jsonify({"error": "Status pengajuan tidak valid."}), 400
    if len(keyword) > 150:
        return jsonify({"error": "Pencarian terlalu panjang."}), 400

    where = ["br.request_status IN ('Approved','Rejected')"]
    params = []
    if kind == "SATUAN":
        where.append("br.batch_id IS NULL")
    elif kind == "BATCH":
        where.append("br.batch_id IS NOT NULL")
    if status != "ALL":
        where.append("br.request_status = %s")
        params.append(status)
    if keyword:
        where.append("""(
            CAST(br.request_id AS TEXT) ILIKE %s
            OR COALESCE(br.pic,'') ILIKE %s
            OR COALESCE(br.request_description,'') ILIKE %s
            OR COALESCE(u.username,'') ILIKE %s
            OR COALESCE(bb.batch_code,'') ILIKE %s
        )""")
        params.extend([f"%{keyword}%"] * 5)

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(f"""
                SELECT br.request_id, br.transaction_date, br.request_date,
                       br.pic, br.input_profit_center, br.input_gl_account,
                       br.input_cost_center, br.request_amount, br.request_description,
                       br.request_status, br.batch_id,
                       latest_decision.decision_date
                FROM public.budget_request br
                JOIN public.users u ON u.user_id = br.user_id
                LEFT JOIN public.budget_request_batch bb ON bb.batch_id = br.batch_id
                LEFT JOIN LATERAL (
                    SELECT ad.decision_date
                    FROM public.approval_decision ad
                    WHERE ad.request_id = br.request_id
                    ORDER BY ad.decision_date DESC, ad.approval_id DESC LIMIT 1
                ) latest_decision ON TRUE
                WHERE {' AND '.join(where)}
                ORDER BY COALESCE(latest_decision.decision_date, br.request_date) DESC,
                         br.request_id DESC
            """, params)
            records = cur.fetchall()
            request_ids = [int(rec['request_id']) for rec in records]
            input_rows = {}
            if request_ids:
                # A completed import can hold several instructions per request.
                # Pick the most recent processed import, never a new preview.
                cur.execute("""
                    SELECT air.request_id, air.excel_row_number,
                           air.instruction, air.fund_code,
                           air.funds_center_code, air.commitment_item_code,
                           air.amount, air.source_budget_id,
                           aib.uploaded_filename, aib.approval_import_id,
                           aib.confirmed_at,
                           donor_ue.unit_entity AS resolved_source_entity,
                           donor_b.biro_name AS resolved_source_biro
                    FROM public.approval_import_rows air
                    JOIN public.approval_import_batches aib
                      ON aib.approval_import_id = air.approval_import_id
                    LEFT JOIN public.budget_master donor_bm
                      ON donor_bm.budget_id = air.source_budget_id
                    LEFT JOIN public.unit_entity donor_ue
                      ON donor_ue.entity_id = donor_bm.entity_id
                    LEFT JOIN public.biro donor_b
                      ON donor_b.biro_id = donor_bm.biro_id
                     AND donor_b.entity_id = donor_bm.entity_id
                    WHERE air.request_id = ANY(%s)
                      AND air.validation_status = 'processed'
                      AND aib.import_status IN ('completed','partially_processed')
                    ORDER BY air.request_id, aib.confirmed_at DESC NULLS LAST,
                             aib.approval_import_id DESC, air.excel_row_number
                """, (request_ids,))
                for item in cur.fetchall():
                    rid = int(item['request_id'])
                    if rid not in input_rows:
                        input_rows[rid] = {'import_id': item['approval_import_id'], 'rows': []}
                    if input_rows[rid]['import_id'] == item['approval_import_id']:
                        input_rows[rid]['rows'].append(item)

        from datetime import timezone
        from zoneinfo import ZoneInfo
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        jakarta = ZoneInfo('Asia/Jakarta')

        def local_date(value):
            if isinstance(value, datetime):
                if value.tzinfo is None:
                    value = value.replace(tzinfo=timezone.utc)
                return value.astimezone(jakarta).date()
            if isinstance(value, date):
                return value
            return None

        def excel_text(value):
            if value is None:
                return ''
            value = str(value)
            return "'" + value if value.lstrip().startswith(('=', '+', '-', '@')) else value

        wb = Workbook()
        ws_approval = wb.active
        ws_approval.title = 'APPROVAL'
        ws_user = wb.create_sheet('USER')
        ws_notes = wb.create_sheet('KETERANGAN')
        # First six fields retain the familiar, input-oriented order.
        ws_approval.append([
            'DATE', 'Instruction', 'FUND', 'FUNDS CENTER',
            'COMMITMENT ITEM', 'AMOUNT', 'REQUEST ID',
            'SOURCE ENTITY (resolved)', 'SOURCE BIRO (resolved)',
            'SUMBER / CATATAN'
        ])
        ws_approval.append([
            '(Tanggal keputusan sistem; BUKAN tanggal di Excel)',
            '(+/- dari impor yang diproses)', '(Kode tersimpan dari impor)',
            '(Kode tersimpan dari impor)', '(Kode tersimpan dari impor)',
            '(Nominal instruksi impor; BUKAN request amount)',
            '(ID pengajuan)', '(Donor dicocokkan dari budget_master)',
            '(Donor dicocokkan dari budget_master)', '(Lihat sheet KETERANGAN)'
        ])
        ws_user.append([
            'Tanggal', 'PIC', 'CoA / GL', 'Nominal', 'Ket',
            'Cost Center', 'Profit Center', 'REQUEST ID', 'SUMBER DATA'
        ])
        ws_user.append([
            '(Tanggal transaksi tersimpan; jika kosong: tanggal pengajuan)',
            '(PIC tersimpan)', '(Input GL tersimpan)',
            '(Nominal pengajuan, bukan nominal instruksi approval)',
            '(Keterangan tersimpan)', '(Input Cost Center tersimpan)',
            '(Input Profit Center tersimpan)', '(ID pengajuan)',
            '(budget_request; bukan file mentah yang diunggah)'
        ])

        for rec in records:
            rid = int(rec['request_id'])
            date_approval = local_date(rec['decision_date'])
            date_user = local_date(rec['transaction_date']) or local_date(rec['request_date'])
            stored = input_rows.get(rid)
            if stored:
                for line in stored['rows']:
                    # '+'/'-' are the *actual* numeric instructions from the
                    # persisted Excel import. Do not replace with request_amount.
                    ws_approval.append([
                        date_approval, str(line['instruction']).strip(),
                        excel_text(line['fund_code']),
                        excel_text(line['funds_center_code']),
                        excel_text(line['commitment_item_code']),
                        float(line['amount']), f'REQ-{rid}',
                        excel_text(line['resolved_source_entity']),
                        excel_text(line['resolved_source_biro']),
                        f"Impor #{line['approval_import_id']} | "
                        f"{excel_text(line['uploaded_filename'])} | "
                        f"baris asli {line['excel_row_number']}; "
                        'SOURCE diresolusi dari budget donor saat ekspor; bukan teks Excel mentah'
                        if str(line['instruction']).strip() == '-' else
                        f"Impor #{line['approval_import_id']} | "
                        f"{excel_text(line['uploaded_filename'])} | "
                        f"baris asli {line['excel_row_number']}"
                    ])
            else:
                # Explicit missing evidence is better than a fabricated '+' row.
                ws_approval.append([
                    date_approval, 'TIDAK TERSEDIA', '', '', '', None,
                    f'REQ-{rid}', '', '',
                    'Instruksi input asli tidak ditemukan pada impor Excel '
                    'berstatus processed; tidak direkonstruksi dari hasil approval.'
                ])
            ws_user.append([
                date_user, excel_text(rec['pic']),
                excel_text(rec['input_gl_account']),
                float(rec['request_amount']) if rec['request_amount'] is not None else None,
                excel_text(rec['request_description']),
                excel_text(rec['input_cost_center']),
                excel_text(rec['input_profit_center']), f'REQ-{rid}',
                'Data input tersimpan di budget_request; dapat dinormalisasi SILOG, bukan salinan file mentah'
            ])

        header_fill = PatternFill('solid', fgColor='C8102E')
        guide_fill = PatternFill('solid', fgColor='FDECEF')
        thin = Side(style='hair', color='E2E6ED')
        for ws, widths, money_col in [
            (ws_approval, [18,21,22,25,24,22,16,28,34,83], 6),
            (ws_user, [18,23,22,24,53,25,25,16,69], 4)
        ]:
            ws.sheet_view.showGridLines = False
            ws.freeze_panes = 'A3'
            ws.sheet_view.zoomScale = 85
            for col, width in enumerate(widths, 1):
                ws.column_dimensions[get_column_letter(col)].width = width
            ws.row_dimensions[1].height = 32
            ws.row_dimensions[2].height = 43
            for cell in ws[1]:
                cell.fill = header_fill
                cell.font = Font(name='Aptos', bold=True, color='FFFFFF', size=10)
                cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
            for cell in ws[2]:
                cell.fill = guide_fill
                cell.font = Font(name='Aptos', color='8D3440', italic=True, size=9)
                cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
            for cells in ws.iter_rows(min_row=3):
                for cell in cells:
                    cell.font = Font(name='Aptos', size=10, color='273445')
                    cell.alignment = Alignment(vertical='center', wrap_text=cell.column in (5,10))
                    cell.border = Border(bottom=thin)
                    if cell.row % 2 == 0:
                        cell.fill = PatternFill('solid', fgColor='F5F7FA')
                cells[0].number_format = 'dd/mm/yyyy'
                cells[money_col-1].number_format = '#,##0.00'
                if ws.title == 'APPROVAL':
                    cells[1].data_type = 's'
            if ws.max_row >= 3:
                ws.auto_filter.ref = f'A1:{get_column_letter(ws.max_column)}{ws.max_row}'

        # A read-only provenance guide: never present reconstructed data as raw Excel input.
        ws_notes.append(['BAGIAN', 'KOLOM / DATA', 'SUMBER YANG DIGUNAKAN', 'BATASAN / CARA MEMBACA'])
        for line in [
            ['APPROVAL', 'DATE', 'approval_decision.decision_date',
             'Tanggal keputusan sistem (WIB). Tanggal yang diketik di Excel Approval asli tidak tersimpan pada kolom ini.'],
            ['APPROVAL', 'Instruction, FUND, FUNDS CENTER, COMMITMENT ITEM, AMOUNT',
             'approval_import_rows pada impor Excel yang sudah diproses',
             'Nominal AMOUNT adalah instruksi + / - yang disimpan, BUKAN nominal pengajuan atau approved_amount.'],
            ['APPROVAL', 'REQUEST ID', 'budget_request.request_id',
             'Penghubung ke pengajuan. Bukan kolom wajib pada template impor yang sama.'],
            ['APPROVAL', 'SOURCE ENTITY / SOURCE BIRO (resolved)',
             'budget_master donor yang terhubung melalui source_budget_id',
             'Identitas donor hasil pencocokan pada saat ekspor. Bukan bukti teks SOURCE yang diketik persis di file Excel asli.'],
            ['APPROVAL', 'TIDAK TERSEDIA', 'Tidak ada baris impor processed yang bisa ditelusuri',
             'Bukan instruksi Approval. Tidak boleh diartikan nol, tanda +, atau penolakan.'],
            ['USER', 'Tanggal', 'budget_request.transaction_date; fallback request_date',
             'Tanggal transaksi tersimpan; bila tidak ada digunakan tanggal pengajuan. Bukan jaminan format tanggal mentah Excel.'],
            ['USER', 'PIC, CoA/GL, Nominal, Ket, Cost Center, Profit Center',
             'Kolom input tersimpan pada budget_request',
             'Menunjukkan data pengajuan yang disimpan/dinormalisasi sistem, bukan salinan byte-per-byte dari Excel sumber.'],
            ['KEDUA SHEET', 'Keterkaitan', 'REQUEST ID',
             'Cocokkan REQ-xx pada kedua sheet untuk membaca input pengusul dan instruksi approval yang terkait.'],
            ['KEDUA SHEET', 'Batasan penggunaan', 'Arsip baca-saja',
             'BUKAN template untuk diunggah ulang; tidak memuat REQUEST_MAP dan proses validasi impor.'],
            ['AUDIT FINANSIAL', 'Hasil transaksi', 'File ekspor Riwayat Approval terpisah',
             'Gunakan Riwayat Approval untuk keputusan akhir, Open Budget, Reallocation, Consume, serta saldo sebelum/sesudah.'],
        ]:
            ws_notes.append(line)
        ws_notes.sheet_view.showGridLines = False
        ws_notes.freeze_panes = 'A2'
        ws_notes.sheet_view.zoomScale = 85
        for col, width in enumerate([23, 55, 62, 112], 1):
            ws_notes.column_dimensions[get_column_letter(col)].width = width
        ws_notes.row_dimensions[1].height = 32
        for cell in ws_notes[1]:
            cell.fill = header_fill
            cell.font = Font(name='Aptos', bold=True, color='FFFFFF', size=10)
            cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        for cells in ws_notes.iter_rows(min_row=2):
            ws_notes.row_dimensions[cells[0].row].height = 42
            for cell in cells:
                cell.font = Font(name='Aptos', size=10, color='273445')
                cell.alignment = Alignment(vertical='center', wrap_text=True)
                cell.border = Border(bottom=thin)
                if cell.row % 2 == 0:
                    cell.fill = PatternFill('solid', fgColor='F5F7FA')
        ws_notes.auto_filter.ref = f'A1:D{ws_notes.max_row}'

        output = BytesIO()
        wb.save(output)
        output.seek(0)
        return send_file(
            output, as_attachment=True,
            download_name=f'SILOG_Riwayat_Format_Approval_User_{datetime.now(jakarta):%Y%m%d_%H%M}.xlsx',
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
    except psycopg2.Error:
        app.logger.exception('Gagal mengekspor format Approval/User')
        return jsonify({'error': 'Export format Approval/User gagal dibuat.'}), 500
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


@app.route("/approval/export-budget/batch/<int:batch_id>.xlsx")
def export_budget_approval_batch(batch_id):
    """Unduh workbook Approval untuk seluruh pengajuan dalam satu batch Excel."""
    guard = approval_api_guard()
    if guard is not None:
        return guard
    return _budget_export_file(user_mode=False, batch_id=batch_id)

# menjalankan aplikasi flask lokal
if __name__ == "__main__":
    app.run(debug=True, port=5001)