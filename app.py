from flask import Flask, render_template, request, redirect, session, jsonify
from cryptography.fernet import Fernet
import sqlite3
from datetime import datetime
import os
import random
import string
from datetime import datetime, timedelta
from flask import send_from_directory
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'


# Generate or load encryption key
def load_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as f:
            f.write(key)
    else:
        with open("secret.key", "rb") as f:
            key = f.read()
    return key

key = load_key()
cipher = Fernet(key)
def init_db():
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()

    # Create messages table
    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text_encrypted TEXT NOT NULL,
            submitted_by TEXT,
            timestamp TEXT
        )
    ''')

    # Create access_requests table
    c.execute('''
        CREATE TABLE IF NOT EXISTS access_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            message_id INTEGER,
            status TEXT DEFAULT 'pending',
            passcode TEXT
        )
    ''')

    # Create users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    # ✅ Add missing columns to access_requests
    c.execute("PRAGMA table_info(access_requests)")
    access_columns = [col[1] for col in c.fetchall()]
    if 'viewed_by_user' not in access_columns:
        c.execute("ALTER TABLE access_requests ADD COLUMN viewed_by_user INTEGER DEFAULT 0")
    if 'rejected_seen' not in access_columns:
        c.execute("ALTER TABLE access_requests ADD COLUMN rejected_seen INTEGER DEFAULT 0")
    if 'expired_seen' not in access_columns:
        c.execute("ALTER TABLE access_requests ADD COLUMN expired_seen INTEGER DEFAULT 0")
    if 'expires_at' not in access_columns:
        c.execute("ALTER TABLE access_requests ADD COLUMN expires_at TEXT")

    # ✅ Add missing columns to messages
    c.execute("PRAGMA table_info(messages)")
    msg_columns = [col[1] for col in c.fetchall()]
    if 'is_public' not in msg_columns:
        c.execute("ALTER TABLE messages ADD COLUMN is_public INTEGER DEFAULT 1")
    if 'visibility' not in msg_columns:
        c.execute("ALTER TABLE messages ADD COLUMN visibility TEXT DEFAULT 'public'")
    if 'file_name' not in msg_columns:
        c.execute("ALTER TABLE messages ADD COLUMN file_name TEXT")
    if 'is_direct' not in msg_columns:
        c.execute("ALTER TABLE messages ADD COLUMN is_direct INTEGER DEFAULT 0")

    conn.commit()
    conn.close()

@app.route('/')
def index():
    session.clear()
    return render_template('index.html', current_user=None, submitted=False)

from flask import request

@app.route('/set_user', methods=['POST'])
def set_user():
    username = request.form.get('username')
    password = request.form.get('password')
    user_ip = request.remote_addr

    # ✅ Admin login with IP restriction
    allowed_admin_ips = ['127.0.0.1', '::1', '192.168.29.179']
    if username == 'srikanth130404' and password == '2815':
        if user_ip in allowed_admin_ips:
            session.clear()
            session['admin'] = True
            return redirect('/admin')
        else:
            session['login_error'] = f'❌ Admin login only from authorized system. Your IP: {user_ip}'
            return redirect('/')

    # ✅ Regular user login
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = c.fetchone()

    if row and row[0] == password:
        session.clear()
        session['current_user'] = username
        conn.close()
        return redirect('/messages')

    elif not row:
        # New user: register and login
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            session.clear()
            session['current_user'] = username
            conn.close()
            return redirect('/messages')
        except sqlite3.IntegrityError:
            session['login_error'] = 'Username already exists'
    else:
        session['login_error'] = 'Invalid username or password'

    conn.close()
    return redirect('/')

@app.route('/ajax_login', methods=['POST'])
def ajax_login():
    username = request.form.get('username')
    password = request.form.get('password')

    if username == 'srikanth130404' and password == '2815':
        session.clear()
        session['admin'] = True
        return jsonify({'success': True, 'redirect_url': '/admin'})

    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = c.fetchone()

    if row:
        if row[0] == password:
            session.clear()
            session['current_user'] = username
            return jsonify({'success': True, 'redirect_url': '/messages'})
        else:
            return jsonify({'success': False, 'message': 'Incorrect password'})
    else:
        # Register new user
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        session.clear()
        session['current_user'] = username
        return jsonify({'success': True, 'redirect_url': '/messages'})

@app.route('/messages')
def messages():
    if 'current_user' not in session:
        return redirect('/')

    submitted = session.pop('submitted', False)  # ✅ this is important
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("SELECT username FROM users")
    users = [row[0] for row in c.fetchall()]
    conn.close()

    return render_template('index.html', current_user=session['current_user'], submitted=submitted, user_list=users)

@app.route('/submit', methods=['POST'])
def submit():
    text = request.form['text']
    user = session.get('current_user', 'guest')
    visibility = request.form.get('visibility', 'public')
    recipient = request.form.get('recipient')  # Only relevant for private

    # Encrypt the message
    encrypted = cipher.encrypt(text.encode()).decode()

    # Handle file upload
    file = request.files.get('file')
    file_name = None
    if file and file.filename:
        os.makedirs('uploads', exist_ok=True)
        file_path = os.path.join('uploads', file.filename)
        file.save(file_path)
        file_name = file.filename

    conn = sqlite3.connect('messages.db')
    c = conn.cursor()

    # Ensure column is_direct exists
    try:
        c.execute("ALTER TABLE messages ADD COLUMN is_direct INTEGER DEFAULT 0")
    except:
        pass  # Already exists

    # Insert message
    c.execute("""
        INSERT INTO messages (text_encrypted, submitted_by, timestamp, visibility, file_name, is_direct)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (encrypted, user, datetime.now().isoformat(), visibility, file_name, 1 if recipient else 0))
    message_id = c.lastrowid

    if visibility == 'private' and recipient:
        passcode = ''.join(random.choices(string.digits, k=4))
        expires_at = (datetime.now() + timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S')

    # Insert direct access request (auto-approved)
    c.execute("""
        INSERT INTO access_requests (user_id, message_id, status, passcode, expires_at)
        VALUES (?, ?, 'approved', ?, ?)
    """, (recipient, expires_at))

    # Mark message as direct
    try:
        c.execute("ALTER TABLE messages ADD COLUMN is_direct INTEGER DEFAULT 0")
    except:
        pass
    c.execute("UPDATE messages SET is_direct = 1 WHERE id = ?", (message_id,))


    conn.commit()
    conn.close()

    # ✅ Success flag for frontend
    session['submitted'] = True
    return redirect('/messages')

@app.route('/request_access', methods=['POST'])
def request_access():
    current_user = session.get('current_user')
    message_id = request.form.get('message_id')

    if not message_id or not current_user:
        return "Missing data", 400

    conn = sqlite3.connect('messages.db')
    c = conn.cursor()

    # ✅ Check if message is public or belongs to current user
    c.execute("SELECT submitted_by, visibility FROM messages WHERE id = ?", (message_id,))
    msg = c.fetchone()

    if not msg:
        conn.close()
        return "Message not found", 404

    submitted_by, visibility = msg

    # ❌ If message is private and not owned by current user — deny
    if visibility == 'private' and submitted_by != current_user:
        conn.close()
        return "Access denied: private message", 403

    # ✅ Prevent duplicate access request
    c.execute("SELECT 1 FROM access_requests WHERE user_id = ? AND message_id = ?", (current_user, message_id))
    if c.fetchone():
        conn.close()
        return redirect('/messages')

    # ✅ Create new pending access request
    c.execute("""
        INSERT INTO access_requests (user_id, message_id, status, passcode, viewed_by_user)
        VALUES (?, ?, 'pending', NULL, 0)
    """, (current_user, message_id))
    
    conn.commit()
    conn.close()

    return redirect('/messages')

@app.route('/verify_passcode_ajax', methods=['POST'])
def verify_passcode_ajax():
    data = request.json
    username = session.get('current_user')
    entered_code = data.get('passcode')
    msg_id = data.get('message_id')

    if not (username and entered_code and msg_id):
        return jsonify({'success': False, 'error': 'Missing data'})

    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("""
        SELECT ar.id, m.timestamp, m.submitted_by, m.text_encrypted, ar.passcode, ar.expires_at
        FROM messages m
        JOIN access_requests ar ON ar.message_id = m.id
        WHERE ar.user_id = ? AND m.id = ? AND ar.status = 'approved'
    """, (username, msg_id))
    row = c.fetchone()
    conn.close()

    if not row:
        # ✅ No matching request — possibly ghost-deleted or expired
        return jsonify({'success': False, 'error': 'Message not found or access expired'})

    request_id, timestamp, submitted_by, encrypted_text, correct_passcode, expires_at = row

    # ✅ If expired, mark as expired_seen in DB and return error
    if expires_at and datetime.fromisoformat(expires_at) < datetime.now():
        conn = sqlite3.connect('messages.db')
        c = conn.cursor()
        c.execute("""
            UPDATE access_requests
            SET expired_seen = 1
            WHERE user_id = ? AND message_id = ?
        """, (username, msg_id))
        conn.commit()
        conn.close()
        return jsonify({'success': False, 'error': 'Message not found or access expired'})

    # ✅ Check passcode
    if str(entered_code).strip() == str(correct_passcode).strip():
        try:
            decrypted = cipher.decrypt(encrypted_text.encode()).decode()
        except Exception as e:
            return jsonify({'success': False, 'error': f'Decryption failed: {str(e)}'})

        # ✅ Mark passcode as verified in session
        session[f'passcode_verified_{msg_id}'] = True

        # ✅ Mark the request as viewed in DB
        conn = sqlite3.connect('messages.db')
        c = conn.cursor()
        c.execute("UPDATE access_requests SET viewed_by_user = 1 WHERE id = ?", (request_id,))
        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'message': decrypted,
            'submitted_by': submitted_by,
            'timestamp': timestamp
        })
    else:
        return jsonify({'success': False, 'error': 'Invalid passcode'})


@app.route('/admin')
def admin():
    if 'admin' not in session:
        return redirect('/login')
    return render_template('admin.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['admin_id'] == 'srikanth130404' and request.form['password'] == '2815':
            session['admin'] = True
            return redirect('/admin')
    return render_template('login.html')


@app.route('/admin/grant_access', methods=['POST'])
def grant_access():
    if 'admin' not in session:
        return jsonify({'error': 'Unauthorized'}), 403

    request_id = request.form['request_id']
    action = request.form['action']

    conn = sqlite3.connect('messages.db')
    c = conn.cursor()

    # Check if request exists
    c.execute("SELECT user_id, message_id FROM access_requests WHERE id = ?", (request_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Request not found'}), 404

    user_id, message_id = row

    if action == 'approved':
        passcode = ''.join(random.choices(string.digits, k=6))
        expires_at = (datetime.now() + timedelta(minutes=10)).isoformat()  
        c.execute("""
            UPDATE access_requests
            SET status = ?, passcode = ?, expires_at = ?
            WHERE id = ?
        """, (action, passcode, expires_at, request_id))

        conn.commit()
        conn.close()

        return jsonify({
            'status': 'ok',
            'action': 'approved',
            'user_id': user_id,
            'message_id': message_id,
            'passcode': passcode,
            'expires_at': expires_at
        })
    elif action == 'rejected':
        # ✅ Update status instead of deleting (so user sees "Access Denied" once)
        c.execute("UPDATE access_requests SET status = 'rejected' WHERE id = ?", (request_id,))
        conn.commit()
        conn.close()
        return jsonify({'status': 'ok', 'action': action})


    else:
        conn.close()
        return jsonify({'error': 'Unknown action'}), 400

@app.route('/admin/delete_request', methods=['POST'])
def delete_request():
    if 'admin' not in session:
        return '', 403
    request_id = request.form['request_id']
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("DELETE FROM access_requests WHERE id = ?", (request_id,))
    conn.commit()
    conn.close()
    return '', 204

@app.route('/admin/delete_message', methods=['POST'])
def delete_message():
    message_id = request.form.get('message_id')

    if not session.get('admin'):
        return "Unauthorized", 403

    conn = sqlite3.connect('messages.db')
    c = conn.cursor()

    # Delete access requests linked to the message
    c.execute("DELETE FROM access_requests WHERE message_id = ?", (message_id,))

    # Delete the message itself
    c.execute("DELETE FROM messages WHERE id = ?", (message_id,))
    
    conn.commit()
    conn.close()

    return '', 204  # Success, no content

@app.route('/get_messages')
def get_messages():
    current_user = session.get('current_user')
    if not current_user:
        return jsonify([])

    conn = sqlite3.connect('messages.db')
    c = conn.cursor()

    # Fetch messages + access requests + is_direct flag
    c.execute("""
        SELECT 
            m.id, m.text_encrypted, m.submitted_by, m.timestamp, m.visibility, 
            m.file_name, m.is_direct, 
            a.id as access_id, a.user_id, a.status, a.passcode, a.viewed_by_user, 
            a.rejected_seen, a.expired_seen
        FROM messages m
        LEFT JOIN access_requests a ON m.id = a.message_id AND a.user_id = ?
        ORDER BY m.timestamp DESC
    """, (current_user,))
    
    rows = c.fetchall()
    conn.close()

    messages = []
    for row in rows:
        (
            msg_id, text_enc, submitted_by, timestamp, visibility,
            file_name, is_direct,
            req_id, user_id, status, passcode, viewed, rejected_seen, expired_seen
        ) = row

        # 🔒 Skip rejected/expired/seen messages
        if status == 'approved' and viewed:
            continue
        if status == 'approved' and expired_seen:
            continue
        if status == 'rejected' and rejected_seen:
            continue

        # 🔐 Direct private messages (only for recipient or sender)
        if visibility == 'private':
            if submitted_by != current_user and user_id != current_user:
                continue

        # 👁️‍🗨️ Determine what to show
        is_verified = session.get(f'passcode_verified_{msg_id}', False)

        if status == 'approved' and is_verified:
            try:
                decrypted = cipher.decrypt(text_enc.encode()).decode()
            except:
                decrypted = "[Decryption Error]"
        elif status == 'approved':
            decrypted = "[Encrypted - Requires Passcode Verification]"
        elif status == 'pending':
            decrypted = "[Encrypted - Pending Approval]"
        elif status == 'rejected':
            decrypted = "[Access Denied by Admin]"

            # Mark rejected as seen
            conn2 = sqlite3.connect('messages.db')
            c2 = conn2.cursor()
            c2.execute("UPDATE access_requests SET rejected_seen = 1 WHERE id = ?", (req_id,))
            conn2.commit()
            conn2.close()
            continue
        else:
            decrypted = "[Encrypted - Request Access Required]" if visibility == 'public' else "[Private Message]"

        messages.append({
            'id': msg_id,
            'text': decrypted,
            'submitted_by': submitted_by,
            'timestamp': timestamp,
            'visibility': visibility,
            'file_name': file_name,
            'access_status': status,
            'is_verified': is_verified
        })

    return jsonify(messages)


@app.route('/admin/get_messages')
def admin_get_messages():
    if 'admin' not in session:
        return jsonify([])

    conn = sqlite3.connect('messages.db')
    c = conn.cursor()

    c.execute("""
        SELECT m.id, m.text_encrypted, m.submitted_by, m.timestamp, m.visibility, m.file_name,
               ar.user_id AS recipient, m.is_direct
        FROM messages m
        LEFT JOIN access_requests ar ON m.id = ar.message_id AND ar.status = 'approved'
        ORDER BY m.timestamp DESC
    """)

    rows = c.fetchall()
    conn.close()

    messages = []
    for row in rows:
        msg_id, encrypted, submitted_by, timestamp, visibility, file_name, recipient, is_direct = row

        # 🔒 Show actual message only if public
        if visibility == 'public':
            try:
                decrypted_text = cipher.decrypt(encrypted.encode()).decode()
            except:
                decrypted_text = "[Unable to decrypt]"
        else:
            decrypted_text = None  # Do not show private message content

        messages.append({
            'id': msg_id,
            'text': decrypted_text,
            'submitted_by': submitted_by,
            'timestamp': timestamp,
            'visibility': visibility,
            'file_name': file_name,
            'recipient': recipient,
            'is_direct': is_direct
        })

    return jsonify(messages)


@app.route('/admin/requests')
def view_requests():
    if 'admin' not in session:
        return redirect('/login')

    now = datetime.now().isoformat()

    conn = sqlite3.connect('messages.db')
    c = conn.cursor()

    # ✅ Remove expired approved requests
    c.execute("""
        DELETE FROM access_requests
        WHERE status = 'approved'
          AND expires_at IS NOT NULL
          AND expires_at < ?
    """, (now,))

    # ✅ Get relevant access requests (pending or approved but not viewed)
    c.execute("""
        SELECT 
            ar.id, ar.user_id, ar.message_id, ar.status, ar.passcode, ar.expires_at,
            m.submitted_by, m.text_encrypted, m.visibility
        FROM access_requests ar
        JOIN messages m ON m.id = ar.message_id
        WHERE ar.status = 'pending'
           OR (ar.status = 'approved' AND (ar.viewed_by_user IS NULL OR ar.viewed_by_user = 0))
    """)
    requests = c.fetchall()
    conn.close()

    result = []
    for row in requests:
        rid, user_id, message_id, status, passcode, expires_at, submitted_by, encrypted, visibility = row

        # ✅ Only decrypt if visibility is public
        if visibility == 'public':
            try:
                decrypted = cipher.decrypt(encrypted.encode()).decode()
            except Exception:
                decrypted = "[Unable to decrypt]"
        else:
            decrypted = None  # Hide private message from admin

        result.append({
            'id': rid,
            'user_id': user_id,
            'message_id': message_id,
            'status': status,
            'passcode': passcode,
            'expires_at': expires_at,
            'submitted_by': submitted_by,
            'message_text': decrypted,
            'visibility': visibility
        })

    return jsonify(result)

@app.route('/debug/requests')
def debug_requests():
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("SELECT * FROM access_requests")
    rows = c.fetchall()
    conn.close()

    print("DEBUG - all access_requests:")
    for r in rows:
        print(r)
    return "Check console"


@app.route('/logout_user')
def logout_user():
    session.pop('current_user', None)
    session.pop('submitted', None)
    return redirect('/')

@app.route('/logout_admin')
def logout_admin():
    session.clear()  # Clear all session data (for safety)
    return redirect('/')

@app.route('/reveal_passcode', methods=['POST'])
def reveal_passcode():
    data = request.json
    message_id = data.get('message_id')
    password = data.get('password')
    current_user = session.get('current_user')

    if not message_id or not password or not current_user:
        return jsonify({'success': False, 'error': 'Missing data'})

    conn = sqlite3.connect('messages.db')
    c = conn.cursor()

    # Check user's password
    c.execute("SELECT password FROM users WHERE username = ?", (current_user,))
    row = c.fetchone()
    if not row or row[0] != password:
        conn.close()
        return jsonify({'success': False, 'error': 'Incorrect password'})

    # Check if approved request exists
    c.execute("SELECT passcode FROM access_requests WHERE user_id = ? AND message_id = ? AND status = 'approved'", (current_user, message_id))
    row = c.fetchone()
    conn.close()

    if not row or not row[0]:
        return jsonify({'success': False, 'error': 'No access granted or passcode not available'})

    return jsonify({'success': True, 'passcode': row[0]})

@app.route('/forgot')
def forgot():
    return render_template('index.html', show_forgot=True, current_user=None)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory('uploads', filename)

@app.route('/admin/files')
def admin_files():
    if 'admin' not in session:
        return jsonify([])

    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("""
        SELECT file_name, submitted_by, timestamp, visibility 
        FROM messages
        WHERE file_name IS NOT NULL
    """)
    files = c.fetchall()
    conn.close()

    return jsonify([
        {
            'name': f[0],
            'submitted_by': f[1],
            'timestamp': f[2],
            'visibility': f[3]
        } for f in files
    ])


@app.route('/admin/users')
def admin_users():
    if 'admin' not in session:
        return jsonify([])

    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("SELECT submitted_by, COUNT(*) FROM messages GROUP BY submitted_by")
    messages = dict(c.fetchall())

    c.execute("SELECT user_id, COUNT(*) FROM access_requests GROUP BY user_id")
    requests = dict(c.fetchall())
    conn.close()

    users = set(messages) | set(requests)
    return jsonify([
        {
            'username': u,
            'messages': messages.get(u, 0),
            'requests': requests.get(u, 0)
        } for u in users
    ])

@app.route('/view_users')
def view_users():
    import sqlite3
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("SELECT username, password FROM users")
    users = c.fetchall()
    conn.close()

    output = "<h3>🧑‍💻 Registered Users:</h3><ul>"
    for user, pwd in users:
        output += f"<li><b>{user}</b> — <code>{pwd}</code></li>"
    output += "</ul>"

    return output

@app.route('/reveal_direct_message/<int:msg_id>')
def reveal_direct_message(msg_id):
    current_user = session.get('current_user')
    if not current_user:
        return jsonify({'success': False, 'error': 'User not logged in'})

    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("""
        SELECT m.text_encrypted, m.submitted_by, m.timestamp
        FROM messages m
        JOIN access_requests a ON m.id = a.message_id
        WHERE m.id = ? AND a.user_id = ? AND a.status = 'approved' AND a.passcode IS NOT NULL
    """, (msg_id, current_user))
    row = c.fetchone()
    conn.close()

    if row:
        try:
            decrypted = cipher.decrypt(row[0].encode()).decode()
            return jsonify({
                'success': True,
                'message': decrypted,
                'submitted_by': row[1],
                'timestamp': row[2]
            })
        except Exception as e:
            return jsonify({'success': False, 'error': 'Decryption failed'})
    return jsonify({'success': False, 'error': 'Access denied or not found'})


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
