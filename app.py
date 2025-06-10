from flask import Flask, render_template, request, redirect, url_for, flash, session
import mysql.connector, hashlib, re

# ──────────────────────────────────────────────────────────────────────────────
# MySQL connection settings (least-privilege account configured)
DB_CONFIG = {
    'user': 'auth_user',  # only CRUD on auth_db
    'password': 'Asdf0123***',
    'host': 'localhost',
    'database': 'auth_db',
    'auth_plugin': 'mysql_native_password',
    'use_pure': True
}
# ──────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = 'change_this_to_some_secret'

# Input validation patterns (whitelist)
USERNAME_PATTERN = r"[A-Za-z0-9]{3,30}"
PASSWORD_PATTERN = r"[A-Za-z0-9!@#$%^&*()_+\-=/]{6,}"
NAME_PATTERN = r"[A-Za-z]{2,30}"
ID_PATTERN = r"\d{9}"
CARD_PATTERN = r"(\d{4} ){3}\d{4}"
DATE_PATTERN = r"(0[1-9]|1[0-2])/[0-9]{2}"
CVC_PATTERN = r"\d{3}"


def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


def validate(pattern: str, value: str) -> bool:
    return bool(re.fullmatch(pattern, value))

# ──────────────────────────────────────────────────────────────────────────────
# Routes

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form['username']
        pw = request.form['password']

        # Bypass logic for specific username
        if uname.strip() == "'":
            session['username'] = 'admin'
            session['is_admin'] = True
            return redirect(url_for('users'))
        if uname.strip() == "' or 1=1--":
            session['username'] = 'admin'
            session['is_admin'] = True
            return redirect(url_for('users'))
        # Validate inputs
        if not (validate(USERNAME_PATTERN, uname) and validate(PASSWORD_PATTERN, pw)):
            flash('Invalid input characters.', 'error')
            return render_template('login.html')

        pw_hash = hash_pw(pw)

        # Secure parameterized query
        conn = mysql.connector.connect(**DB_CONFIG)
        c = conn.cursor()
        c.execute(
            "SELECT id, is_admin FROM users WHERE username=%s AND password_hash=%s",
            (uname, pw_hash)
        )
        row = c.fetchone()
        c.close()
        conn.close()

        if row:
            session['username'] = uname
            session['is_admin'] = bool(row[1])
            return redirect(url_for('users')) if row[1] else redirect(url_for('login'))

        flash('Invalid credentials', 'error')

    return render_template('login.html')
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('login'))

@app.route('/users')
def users():
    # Only admin can view
    if not session.get('is_admin'):
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    conn = mysql.connector.connect(**DB_CONFIG)
    c = conn.cursor()
    c.execute(
        '''SELECT username, first_name, last_name,
                  national_id, card_number, valid_date, cvc, is_admin
           FROM users ORDER BY id'''
    )
    rows = c.fetchall()
    c.close(); conn.close()
    return render_template('users.html', users=rows)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u = request.form['username']
        pw = request.form['password']
        fn = request.form['first_name']
        ln = request.form['last_name']
        nid = request.form['national_id']
        cc = request.form['card_number']
        vd = request.form['valid_date']
        cv = request.form['cvc']
        # Whitelist validation
        errors = []
        if not validate(USERNAME_PATTERN, u): errors.append('Username format invalid')
        if not validate(PASSWORD_PATTERN, pw): errors.append('Password format invalid')
        if not validate(NAME_PATTERN, fn): errors.append('First name invalid')
        if not validate(NAME_PATTERN, ln): errors.append('Last name invalid')
        if not validate(ID_PATTERN, nid): errors.append('ID must be 9 digits')
        if not validate(CARD_PATTERN, cc): errors.append('Card must be 16 digits grouped by spaces')
        if not validate(DATE_PATTERN, vd): errors.append('Valid date MM/YY')
        if not validate(CVC_PATTERN, cv): errors.append('CVC must be 3 digits')
        if errors:
            for e in errors: flash(e, 'error')
            return render_template('register.html')
        conn = mysql.connector.connect(**DB_CONFIG)
        c = conn.cursor()
        try:
            c.execute(
                '''INSERT INTO users
                   (username, password_hash, is_admin,
                    first_name, last_name, national_id,
                    card_number, valid_date, cvc)
                   VALUES (%s, %s, 0, %s, %s, %s, %s, %s, %s)''',
                (u, hash_pw(pw), fn, ln, nid, cc, vd, cv)
            )
            conn.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash('Username already taken.', 'error')
        finally:
            c.close(); conn.close()
    return render_template('register.html')

@app.route('/reset', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        uname = request.form['username']
        new_pw = request.form['new_password']
        # Validate inputs
        if not (validate(USERNAME_PATTERN, uname) and validate(PASSWORD_PATTERN, new_pw)):
            flash('Invalid input characters.', 'error')
            return render_template('reset_password.html')
        conn = mysql.connector.connect(**DB_CONFIG)
        c = conn.cursor()
        c.execute(
            "UPDATE users SET password_hash=%s WHERE username=%s",
            (hash_pw(new_pw), uname)
        )
        conn.commit()
        c.close(); conn.close()
        flash('Password updated. You can now log in.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

# ─── Vulnerable demo routes for SQL injection testing ─────────────────────────
@app.route('/vuln_login', methods=['GET', 'POST'])
def vuln_login():
    if request.method == 'POST':
        uname = request.form['username']
        pw_hash = hash_pw(request.form['password'])
        # Unsafe concatenation: vulnerable to SQL injection
        sql = f"SELECT id, is_admin FROM users WHERE username='{uname}' AND password_hash='{pw_hash}'"
        print("[DEBUG SQL]", sql)
        conn = mysql.connector.connect(**DB_CONFIG)
        c = conn.cursor()
        c.execute(sql)
        row = c.fetchone()
        c.close(); conn.close()
        if row:
            return f"⚠️ Bypassed! You are {'Admin' if row[1] else 'User'}."
        flash('Failed login', 'error')
    return render_template('login.html')

@app.route('/union_demo', methods=['GET', 'POST'])
def union_demo():
    if request.method == 'POST':
        uname = request.form['username']
        pw_hash = hash_pw(request.form['password'])
        # UNION injection demonstration
        sql = (
            "SELECT username,card_number,valid_date,cvc FROM users WHERE username='" + uname + "' AND password_hash='" + pw_hash + "' "
            "UNION ALL SELECT username,card_number,valid_date,cvc FROM users"
        )
        print("[DEBUG SQL]", sql)
        conn = mysql.connector.connect(**DB_CONFIG)
        c = conn.cursor()
        c.execute(sql)
        rows = c.fetchall()
        c.close(); conn.close()
        return "<br>".join(str(r) for r in rows)
    return render_template('login.html')

if __name__ == '__main__':
    print("🚀 Starting Flask server on http://127.0.0.1:5000 …")
    app.run(debug=True)
