# app.py
import os
import hmac
import bcrypt
import psycopg2

from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (Flask, render_template, request, flash, redirect, url_for, session)
from database import get_db_connection


# konfigurasi flask
load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError("FLASK_SECRET_KEY belum diatur di .env")


# verifikasi password
def verify_password(input_password, stored_password):
    if not isinstance(stored_password, str):
        return False

    if stored_password.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(stored_password, input_password)

    if stored_password.startswith(("$2a$", "$2b$", "$2y$")):
        return bcrypt.checkpw(
            input_password.encode("utf-8"),
            stored_password.encode("utf-8")
        )

    # dukungan password lama untuk migrasi
    return hmac.compare_digest(input_password, stored_password)


# halaman login
@app.route("/", methods=["GET", "POST"])
def login():

    # selalu tampilkan halaman login saat membuka website
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

        if not user:
            flash("Username tidak ditemukan.", "danger")
            return redirect(url_for("login"))

        user_id, db_username, db_password, role, entity_id, biro_id = user

        # validasi password
        if not verify_password(password, db_password):
            flash("Password tidak sesuai.", "danger")
            return redirect(url_for("login"))

        # validasi role
        if role not in ("Pengusul", "Approval"):
            flash("Role pengguna tidak dikenali.", "danger")
            return redirect(url_for("login"))

        # migrasi password lama menjadi hash
        if not db_password.startswith(
            ("scrypt:", "pbkdf2:", "$2a$", "$2b$", "$2y$")
        ):
            new_hash = generate_password_hash(password)

            with conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        UPDATE public.users
                        SET password = %s
                        WHERE user_id = %s
                          AND password = %s
                        """,
                        (new_hash, user_id, db_password)
                    )

        # simpan session pengguna
        session.clear()
        session["user_id"] = user_id
        session["username"] = db_username
        session["role"] = role
        session["entity_id"] = entity_id
        session["biro_id"] = biro_id

    except (psycopg2.Error, ValueError, TypeError):
        app.logger.exception("Gagal melakukan login")
        flash("Login gagal diproses.", "danger")
        return redirect(url_for("login"))

    finally:
        if conn is not None:
            conn.close()

    # arahkan setelah proses login selesai
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

    # validasi input
    if not username:
        flash("Username wajib diisi.", "danger")
        return redirect(url_for("register_approval"))

    if len(username) > 255:
        flash("Username terlalu panjang.", "danger")
        return redirect(url_for("register_approval"))

    if len(password) < 8:
        flash("Password minimal 8 karakter.", "danger")
        return redirect(url_for("register_approval"))

    if password != confirm_password:
        flash("Konfirmasi password tidak sesuai.", "danger")
        return redirect(url_for("register_approval"))

    # validasi kode approval
    valid_code = os.getenv("APPROVAL_CODE")

    if not valid_code:
        raise RuntimeError("APPROVAL_CODE belum diatur di .env")

    if not hmac.compare_digest(approval_code, valid_code):
        flash("Kode Approval tidak sesuai.", "danger")
        return redirect(url_for("register_approval"))

    # simpan akun approval ke supabase
    password_hash = generate_password_hash(password)
    conn = None

    try:
        conn = get_db_connection()

        with conn:
            with conn.cursor() as cursor:

                # cek username duplikat
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

                # buat akun approval pusat
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
                    RETURNING user_id
                    """,
                    (username, password_hash)
                )

                new_user_id = cursor.fetchone()[0]

        app.logger.info(
            "Akun approval berhasil dibuat: %s",
            new_user_id
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

    if role == "Pengusul":
        return render_template(
            "dashboard_pengusul.html",
            username=session.get("username")
        )

    session.clear()
    return redirect(url_for("login"))


# logout
@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Berhasil logout.", "info")
    return redirect(url_for("login"))


# jalankan flask
if __name__ == "__main__":
    app.run(debug=True, port=5001)