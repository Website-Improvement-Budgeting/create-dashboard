import os
import hmac

import bcrypt
import psycopg2
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from database import get_db_connection


# konfigurasi aplikasi
load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError("FLASK_SECRET_KEY belum diatur di .env")


# verifikasi password lama dan baru tanpa migrasi otomatis
def verify_password(input_password, stored_password):
    if not isinstance(stored_password, str):
        return False

    if stored_password.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(stored_password, input_password)

    if stored_password.startswith(("$2a$", "$2b$", "$2y$")):
        try:
            return bcrypt.checkpw(
                input_password.encode("utf-8"),
                stored_password.encode("utf-8")
            )
        except ValueError:
            return False

    # mendukung akun pengujian lama yang belum memakai hash
    return hmac.compare_digest(input_password, stored_password)


# mengambil ringkasan budget sesuai unit dan biro pengusul
def get_pengusul_budget_summary(entity_id, biro_id, budget_year):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    COALESCE(SUM(consumable_budget), 0),
                    COALESCE(SUM(consumed_budget), 0),
                    COALESCE(SUM(available_amount), 0)
                FROM public.budget_master
                WHERE entity_id = %s
                  AND biro_id = %s
                  AND budget_year = %s
                """,
                (entity_id, biro_id, budget_year)
            )
            consumable, consumed, available = cursor.fetchone()

        return {
            "consumable_budget": consumable,
            "consumed_budget": consumed,
            "available_amount": available,
        }
    finally:
        conn.close()


# mengambil tahun budget yang tersedia
def get_budget_years(entity_id, biro_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT DISTINCT budget_year
                FROM public.budget_master
                WHERE entity_id = %s
                  AND biro_id = %s
                  AND budget_year IS NOT NULL
                ORDER BY budget_year DESC
                """,
                (entity_id, biro_id)
            )
            return [row[0] for row in cursor.fetchall()]
    finally:
        conn.close()


# mengambil data grafik per commitment item
def get_pengusul_commitment_chart(entity_id, biro_id, budget_year):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    ci.commitment_item_code,
                    COALESCE(SUM(bm.consumed_budget), 0) AS total_consumed
                FROM public.budget_master AS bm
                JOIN public.commitment_item AS ci
                  ON bm.commitment_item_id = ci.commitment_item_id
                WHERE bm.entity_id = %s
                  AND bm.biro_id = %s
                  AND bm.budget_year = %s
                GROUP BY ci.commitment_item_code
                ORDER BY total_consumed DESC
                LIMIT 10
                """,
                (entity_id, biro_id, budget_year)
            )
            rows = cursor.fetchall()

        return [
            {"label": str(code), "amount": float(amount)}
            for code, amount in rows
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
                SELECT user_id, username, password, role, entity_id, biro_id
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

        if role == "Pengusul" and (entity_id is None or biro_id is None):
            flash("Identitas Entity atau Biro belum tersedia.", "danger")
            return redirect(url_for("login"))

        session.clear()
        session.update({
            "user_id": user_id,
            "username": db_username,
            "role": role,
            "entity_id": entity_id,
            "biro_id": biro_id,
        })

    except psycopg2.Error:
        app.logger.exception("Gagal melakukan login")
        flash("Login gagal diproses.", "danger")
        return redirect(url_for("login"))
    finally:
        if conn is not None:
            conn.close()

    if role == "Pengusul":
        return redirect(url_for("profil"))
    return redirect(url_for("dashboard"))


# registrasi approval
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
                cursor.execute(
                    """
                    SELECT 1 FROM public.users
                    WHERE LOWER(username) = LOWER(%s)
                    LIMIT 1
                    """,
                    (username,)
                )
                if cursor.fetchone():
                    flash("Username sudah digunakan.", "danger")
                    return redirect(url_for("register_approval"))

                cursor.execute(
                    """
                    INSERT INTO public.users
                        (username, password, role, entity_id, biro_id)
                    VALUES (%s, %s, 'Approval', NULL, NULL)
                    """,
                    (username, generate_password_hash(password))
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


# halaman profil sebagai halaman awal pengusul
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
                    ue.unit_entity,
                    b.biro_code,
                    b.biro_name
                FROM public.users AS u
                LEFT JOIN public.unit_entity AS ue
                    ON u.entity_id = ue.entity_id
                LEFT JOIN public.biro AS b
                    ON u.biro_id = b.biro_id
                   AND u.entity_id = b.entity_id
                WHERE u.user_id = %s AND u.role = 'Pengusul'
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
            "unit_entity": result[2] or "-",
            "biro_code": result[3] or "-",
            "biro_name": result[4] or "-",
        }
        return render_template("profil_pengusul.html", user=user)

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
                    SELECT password FROM public.users
                    WHERE user_id = %s AND role = 'Pengusul'
                    FOR UPDATE
                    """,
                    (session["user_id"],)
                )
                result = cursor.fetchone()

                if not result or not verify_password(password_lama, result[0]):
                    flash("Password lama tidak sesuai.", "danger")
                    return redirect(url_for("profil"))

                cursor.execute(
                    """
                    UPDATE public.users
                    SET password = %s
                    WHERE user_id = %s AND role = 'Pengusul'
                    """,
                    (generate_password_hash(password_baru), session["user_id"])
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


# dashboard berdasarkan role
@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        flash("Silakan login terlebih dahulu.", "danger")
        return redirect(url_for("login"))

    if session.get("role") == "Approval":
        return render_template(
            "dashboard_approval.html",
            username=session.get("username")
        )

    if session.get("role") != "Pengusul":
        session.clear()
        return redirect(url_for("login"))

    entity_id = session.get("entity_id")
    biro_id = session.get("biro_id")
    if entity_id is None or biro_id is None:
        session.clear()
        flash("Identitas Entity atau Biro belum tersedia.", "danger")
        return redirect(url_for("login"))

    try:
        budget_years = get_budget_years(entity_id, biro_id)
        if not budget_years:
            flash("Data budget untuk Entity dan Biro ini belum tersedia.", "warning")
            return redirect(url_for("profil"))

        selected_year = request.args.get("year", type=int)
        if selected_year not in budget_years:
            selected_year = budget_years[0]

        budget_summary = get_pengusul_budget_summary(
            entity_id, biro_id, selected_year
        )
        commitment_chart = get_pengusul_commitment_chart(
            entity_id, biro_id, selected_year
        )

        return render_template(
            "dashboard_pengusul.html",
            username=session.get("username"),
            budget_summary=budget_summary,
            budget_years=budget_years,
            selected_year=selected_year,
            commitment_chart=commitment_chart,
        )

    except psycopg2.Error:
        app.logger.exception("Gagal memuat dashboard pengusul")
        flash("Dashboard gagal dimuat.", "danger")
        return redirect(url_for("profil"))


# logout menggunakan metode post
@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Berhasil logout.", "info")
    return redirect(url_for("login"))


# menjalankan server lokal
if __name__ == "__main__":
    app.run(debug=True, port=5000)