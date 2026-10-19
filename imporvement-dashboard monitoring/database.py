# file database.py 
import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

def get_db_connection():
    database_url = os.getenv("DATABASE_URL")

    if not database_url:
        raise ValueError("DATABASE_URL tidak ditemukan di file .env")

    connection = psycopg2.connect(
        database_url,
        connect_timeout=10,
        sslmode="require"
    )

    return connection