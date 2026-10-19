
from database import get_db_connection

try:
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT current_database(), current_user;")
    result = cursor.fetchone()

    print("Koneksi Supabase berhasil!")
    print("Database:", result[0])
    print("User:", result[1])

    cursor.close()
    conn.close()

except Exception as error:
    print("Koneksi gagal!")
    print(error)