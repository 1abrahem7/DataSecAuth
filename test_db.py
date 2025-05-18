import mysql.connector

cfg = {
    'user': 'auth_user',
    'password': 'Asdf0123***',
    'host': 'localhost',
    'database': 'auth_db',
    'auth_plugin': 'mysql_native_password'
}

conn = mysql.connector.connect(**cfg)
print("✅ Connected to auth_db!")
conn.close()
