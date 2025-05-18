import mysql.connector
import hashlib
import re

DB_CONFIG = {
    'user': 'auth_user',
    'password': 'Asdf0123***',
    'host': 'localhost',
    'database': 'auth_db',
    'auth_plugin': 'mysql_native_password',
    'use_pure': True
}

def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def insert_user(cursor, u, pw, admin, fn, ln, nid, cc, vd, cv):
    # Validate formats
    assert re.fullmatch(r"[A-Za-z]{2,30}", fn)
    assert re.fullmatch(r"[A-Za-z]{2,30}", ln)
    assert re.fullmatch(r"\d{9}", nid)
    assert re.fullmatch(r"(\d{4} ){3}\d{4}", cc)
    assert re.fullmatch(r"(0[1-9]|1[0-2])/[0-9]{2}", vd)
    assert re.fullmatch(r"\d{3}", cv)

    cursor.execute('''
      INSERT INTO users
        (username,password_hash,is_admin,first_name,last_name,
         national_id,card_number,valid_date,cvc)
      VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
    ''', (u, hash_pw(pw), admin, fn, ln, nid, cc, vd, cv))

def init_db():
    conn = mysql.connector.connect(**DB_CONFIG)
    c = conn.cursor()

    # Drop & recreate table
    c.execute("DROP TABLE IF EXISTS users")
    c.execute('''
      CREATE TABLE users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username      VARCHAR(50) UNIQUE NOT NULL,
        password_hash CHAR(64) NOT NULL,
        is_admin      TINYINT(1) NOT NULL,
        first_name    VARCHAR(30) NOT NULL,
        last_name     VARCHAR(30) NOT NULL,
        national_id   CHAR(9)   NOT NULL,
        card_number   CHAR(19)  NOT NULL,
        valid_date    CHAR(5)   NOT NULL,
        cvc           CHAR(3)   NOT NULL
      )
    ''')

    # 1) Admin user first
    insert_user(
      c,
      "admin", "admin123", 1,
      "Israeli", "Israeli", "123456789",
      "1234 5567 8901 2345", "12/32", "123"
    )

    # 2) Nine more dummy users
    names = ["Alice","Bob","Carol","Dave","Eve","Frank","Grace","Heidi","Ivan"]
    for i, name in enumerate(names, start=1):
        nid = f"{100000000 + i:09d}"
        cc  = f"{4000+i:04d} {5000+i:04d} {6000+i:04d} {7000+i:04d}"
        vd  = f"{(i%12)+1:02d}/{30+i:02d}"
        cv  = f"{100 + i:03d}"
        insert_user(
          c,
          f"user{i}", f"pass{i}!", 0,
          name, name+"son", nid, cc, vd, cv
        )

    conn.commit()
    c.close()
    conn.close()
    print("✅ Initialized DB with 10 users (admin first).")

if __name__ == '__main__':
    init_db()
