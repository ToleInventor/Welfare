import os
import sqlite3
import hashlib
import binascii
import secrets
from flask import (
    Flask, render_template, request, redirect, url_for, session,
    jsonify, send_file, abort, flash
)
from werkzeug.utils import secure_filename
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import csv

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'  # Change before production
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB limit
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

DATABASE = './app.db'


# --- Utilities --- #
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        c = conn.cursor()

        c.execute('''
        CREATE TABLE IF NOT EXISTS Users (
            uwin TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            salt TEXT NOT NULL,
            contact_info TEXT,
            telephone_no TEXT,
            role TEXT CHECK(role IN ('admin','teacher')) NOT NULL,
            amount_due REAL DEFAULT 0
        )''')

        c.execute('''
        CREATE TABLE IF NOT EXISTS Cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_number TEXT UNIQUE NOT NULL,
            affected_member TEXT,
            description TEXT,
            amount_per_member REAL NOT NULL,
            total_amount REAL NOT NULL
        )''')

        c.execute('''
        CREATE TABLE IF NOT EXISTS Payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uwin TEXT NOT NULL,
            case_number TEXT NOT NULL,
            amount_paid REAL,
            payment_date TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(uwin) REFERENCES Users(uwin),
            FOREIGN KEY(case_number) REFERENCES Cases(case_number)
        )''')

        c.execute('''
        CREATE TABLE IF NOT EXISTS Messages (
            message_number INTEGER PRIMARY KEY AUTOINCREMENT,
            message_text TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )''')

        c.execute('''
        CREATE TABLE IF NOT EXISTS Submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uwin TEXT NOT NULL,
            screenshot_path TEXT,
            submitted_at TEXT DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending',
            FOREIGN KEY(uwin) REFERENCES Users(uwin)
        )''')

        conn.commit()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def hash_password(password, salt=None):
    if not salt:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt.encode(),
        100_000
    )
    hash_hex = binascii.hexlify(pwd_hash).decode()
    return salt, hash_hex


def verify_password(stored_hash, salt, attempt):
    _, attempt_hash = hash_password(attempt, salt)
    return secrets.compare_digest(stored_hash, attempt_hash)


# --- Routes --- #

@app.route('/')
def index():
    if 'uwin' in session:
        return render_template('dashboard.html', username=session.get('username'), role=session.get('role'))
    else:
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form.get('username')
        pwd = request.form.get('password')
        if not uname or not pwd:
            flash("Username and password required.")
            return redirect(url_for('login'))
        with get_db() as conn:
            user = conn.execute("SELECT * FROM Users WHERE username=?", (uname,)).fetchone()
            if user and verify_password(user['hashed_password'], user['salt'], pwd):
                session['uwin'] = user['uwin']
                session['username'] = user['username']
                session['role'] = user['role']
                return redirect(url_for('index'))
        flash("Invalid username or password.")
        return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# Admin-only: Add new cases
@app.route('/api/cases', methods=['GET', 'POST'])
def api_cases():
    if 'uwin' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user_role = session.get('role')

    if request.method == 'GET':
        # Return all cases sorted by case_number ascending
        with get_db() as conn:
            cases = conn.execute('SELECT * FROM Cases ORDER BY case_number ASC').fetchall()
        return jsonify([dict(c) for c in cases])

    if request.method == 'POST':
        if user_role != 'admin':
            return jsonify({"error": "Forbidden"}), 403

        data = request.json
        required = ['case_number', 'affected_member', 'description', 'amount_per_member', 'total_amount']
        if not all(k in data for k in required):
            return jsonify({"error": "Missing fields"}), 400

        try:
            with get_db() as conn:
                conn.execute(
                    'INSERT INTO Cases (case_number, affected_member, description, amount_per_member, total_amount) '
                    'VALUES (?, ?, ?, ?, ?)',
                    (
                        data['case_number'], data['affected_member'], data['description'],
                        float(data['amount_per_member']), float(data['total_amount'])
                    )
                )
                # Update amount_due for all users here by incrementing amount_per_member
                # For demonstration, simply add amount_per_member to all users' amount_due
                conn.execute('UPDATE Users SET amount_due = amount_due + ?', (float(data['amount_per_member']),))
                conn.commit()
            return jsonify({"message": "Case added and dues updated successfully"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500


# Admin-only: Add new user
@app.route('/api/users', methods=['POST'])
def api_add_user():
    if 'uwin' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Forbidden"}), 403

    data = request.json
    required = ['username', 'password', 'uwin', 'contact_info', 'telephone_no', 'role']
    if not all(k in data for k in required):
        return jsonify({"error": "Missing fields"}), 400
    if data['role'] not in ['admin', 'teacher']:
        return jsonify({"error": "Invalid role"}), 400

    salt, hashed_password = hash_password(data['password'])
    try:
        with get_db() as conn:
            conn.execute(
                'INSERT INTO Users (uwin, username, hashed_password, salt, contact_info, telephone_no, role) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                (
                    data['uwin'], data['username'], hashed_password, salt,
                    data['contact_info'], data['telephone_no'], data['role']
                )
            )
            conn.commit()
        return jsonify({"message": "User created successfully"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or UWIN already exists"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Messages: GET all messages, POST new message (admin only)
@app.route('/api/messages', methods=['GET', 'POST'])
def api_messages():
    if 'uwin' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    if request.method == 'GET':
        with get_db() as conn:
            messages = conn.execute('SELECT * FROM Messages ORDER BY message_number DESC').fetchall()
        return jsonify([dict(m) for m in messages])

    if request.method == 'POST':
        if session.get('role') != 'admin':
            return jsonify({"error": "Forbidden"}), 403
        data = request.json
        if not data or not data.get('message_text'):
            return jsonify({"error": "Message text required"}), 400
        with get_db() as conn:
            conn.execute('INSERT INTO Messages (message_text) VALUES (?)', (data['message_text'],))
            conn.commit()
        return jsonify({"message": "Message added"})


# Payments: Add payment, update user amount_due
@app.route('/api/payments', methods=['POST'])
def api_payments():
    if 'uwin' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    required = ['uwin', 'case_number', 'amount_paid']
    if not all(k in data for k in required):
        return jsonify({"error": "Missing fields"}), 400

    uwin = data['uwin']
    case_number = data['case_number']
    try:
        amount_paid = float(data['amount_paid'])
    except ValueError:
        return jsonify({"error": "Invalid amount"}), 400

    with get_db() as conn:
        case = conn.execute('SELECT total_amount FROM Cases WHERE case_number=?', (case_number,)).fetchone()
        if not case:
            return jsonify({"error": "Case not found"}), 400

        user = conn.execute('SELECT amount_due FROM Users WHERE uwin=?', (uwin,)).fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 400

        new_due = user['amount_due'] - amount_paid
        if new_due < 0:
            new_due = 0

        conn.execute(
            'INSERT INTO Payments (uwin, case_number, amount_paid) VALUES (?, ?, ?)',
            (uwin, case_number, amount_paid)
        )
        conn.execute('UPDATE Users SET amount_due=? WHERE uwin=?', (new_due, uwin))
        conn.commit()

    return jsonify({"message": "Payment recorded", "new_amount_due": new_due})


# Upload payment proof
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'uwin' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400

    filename = secure_filename(file.filename)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # To avoid filename collisions, prefix filename with UWIN + timestamp
    import time
    unique_filename = f"{session['uwin']}_{int(time.time())}_{filename}"
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    file.save(save_path)

    with get_db() as conn:
        conn.execute(
            'INSERT INTO Submissions (uwin, screenshot_path) VALUES (?, ?)',
            (session['uwin'], unique_filename)
        )
        conn.commit()

    return jsonify({"message": "File uploaded successfully"})


# Download cases report PDF (admin only)
@app.route('/download/cases_pdf')
def download_cases_pdf():
    if 'uwin' not in session or session.get('role') != 'admin':
        return abort(403)

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    with get_db() as conn:
        cases = conn.execute('SELECT * FROM Cases ORDER BY case_number').fetchall()

    y = height - 40
    p.setFont("Helvetica-Bold", 14)
    p.drawString(30, y, "Cases Report")
    y -= 25
    p.setFont("Helvetica", 12)

    for case in cases:
        text = (f"Case #{case['case_number']}: {case['affected_member']} | "
                f"Amount/Member: {case['amount_per_member']} | Total: {case['total_amount']}")
        p.drawString(30, y, text)
        y -= 20
        if y < 50:
            p.showPage()
            y = height - 40

    p.save()
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name='cases_report.pdf',
        mimetype='application/pdf'
    )


# Download payments CSV file (admin only)
@app.route('/download/payments_csv')
def download_payments_csv():
    if 'uwin' not in session or session.get('role') != 'admin':
        return abort(403)

    with get_db() as conn:
        payments = conn.execute('SELECT * FROM Payments ORDER BY payment_date DESC').fetchall()

    si = BytesIO()
    cw = csv.writer(si)
    # Header
    cw.writerow(['Payment ID', 'UWIN', 'Case Number', 'Amount Paid', 'Payment Date'])
    for p in payments:
        cw.writerow([p['id'], p['uwin'], p['case_number'], p['amount_paid'], p['payment_date']])

    si.seek(0)
    return send_file(
        si,
        as_attachment=True,
        download_name='payments.csv',
        mimetype='text/csv'
    )


# Admin API: Get defaulters (amount_due > 0)
@app.route('/api/defaulters')
def api_defaulters():
    if 'uwin' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Forbidden"}), 403

    with get_db() as conn:
        users = conn.execute('SELECT username, amount_due FROM Users WHERE amount_due > 0 ORDER BY amount_due DESC').fetchall()

    return jsonify([
        {'username': u['username'], 'outstanding_due': u['amount_due']} for u in users
    ])


# Admin API: Get submissions
@app.route('/api/submissions')
def api_submissions():
    if 'uwin' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Forbidden"}), 403

    with get_db() as conn:
        subs = conn.execute('SELECT * FROM Submissions ORDER BY submitted_at DESC').fetchall()

    return jsonify([dict(s) for s in subs])


# Dynamic dashboard data for span tags
@app.route('/dashboard_data/<section>')
def dashboard_data(section):
    if 'uwin' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    with get_db() as conn:
        if section == 'username':
            return jsonify({"username": session.get('username')})
        elif section == 'amount_due':
            amt = conn.execute('SELECT amount_due FROM Users WHERE uwin=?', (session['uwin'],)).fetchone()
            total_due = amt['amount_due'] if amt else 0
            return jsonify({"total_due": total_due})
        else:
            return jsonify({"error": "Unknown section"}), 400


# Teacher profile update (except UWIN)
@app.route('/api/update_profile', methods=['POST'])
def update_profile():
    if 'uwin' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    contact_info = data.get('contact_info')
    telephone_no = data.get('telephone_no')
    password = data.get('password')

    with get_db() as conn:
        if password:
            salt, hashed_password = hash_password(password)
            conn.execute('UPDATE Users SET contact_info=?, telephone_no=?, hashed_password=?, salt=? WHERE uwin=?',
                         (contact_info, telephone_no, hashed_password, salt, session['uwin']))
        else:
            conn.execute('UPDATE Users SET contact_info=?, telephone_no=? WHERE uwin=?',
                         (contact_info, telephone_no, session['uwin']))
        conn.commit()
    return jsonify({"message": "Profile updated"})


# Serve uploaded images securely
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    if 'uwin' not in session:
        return abort(401)
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))


# Run app
if __name__ == '__main__':
    init_db()
    port=(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
