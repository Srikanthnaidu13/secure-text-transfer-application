from flask import Flask, render_template, request, redirect, session, jsonify
from cryptography.fernet import Fernet
import sqlite3
from datetime import datetime
import os

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
key = Fernet.generate_key()


app = Flask(__name__)
app.secret_key = 'your_secret_key'


# Initialize the database
def init_db():
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        text_encrypted TEXT NOT NULL,
        submitted_by TEXT,
        timestamp TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS access_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        message_id INTEGER,
        status TEXT DEFAULT 'pending'
    )''')
    conn.commit()
    conn.close()

@app.route('/', methods=['GET'])
def index():
    # Clear session for fresh user experience
    session.pop('current_user', None)
    session.pop('submitted', None)
    return render_template('index.html', current_user=None, submitted=False)

@app.route('/set_user', methods=['POST'])
def set_user():
    username = request.form.get('username')
    if username:
        session['current_user'] = username
        return redirect('/messages')
    return redirect('/')

@app.route('/messages')
def messages_page():
    current_user = session.get('current_user')
    submitted = session.pop('submitted', False)
    if not current_user:
        return redirect('/')
    return render_template('index.html', current_user=current_user, submitted=submitted)

@app.route('/submit', methods=['POST'])
def submit():
    text = request.form['text']
    user = session.get('current_user', 'guest')
    encrypted = cipher.encrypt(text.encode()).decode()

    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("INSERT INTO messages (text_encrypted, submitted_by, timestamp) VALUES (?, ?, ?)",
              (encrypted, user, datetime.now().isoformat()))
    conn.commit()
    conn.close()

    session['submitted'] = True
    return redirect('/messages')

@app.route('/get_messages')
def get_messages():
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("SELECT * FROM messages")
    messages = c.fetchall()

    c.execute("SELECT user_id, message_id, status FROM access_requests")
    access_data = c.fetchall()  # ✅ THIS must come before using access_data

    conn.close()

    access_map = {(user_id, msg_id): status for user_id, msg_id, status in access_data}
    current_user = session.get('current_user', 'guest')
    is_admin = 'admin' in session

    result = []
    for row in messages:
        msg_id, encrypted_text, submitted_by, timestamp = row
        access_status = access_map.get((current_user, msg_id))

        try:
            if is_admin or access_status == 'approved':
                text = cipher.decrypt(encrypted_text.encode()).decode()
            elif access_status == 'pending':
                text = "[Encrypted - Pending Approval]"
            else:
                text = "[Encrypted]"
        except:
            text = "[Unable to decrypt]"

        result.append({
            'id': msg_id,
            'submitted_by': submitted_by,
            'timestamp': timestamp,
            'text': text,
            'access_status': access_status
        })

    return jsonify(result)


@app.route('/request_access', methods=['POST'])
def request_access():
    current_user = session.get('current_user', 'guest')
    message_id = request.form['message_id']
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("INSERT INTO access_requests (user_id, message_id) VALUES (?, ?)",
              (current_user, message_id))
    conn.commit()
    conn.close()
    return redirect('/messages')

@app.route('/cancel_request', methods=['POST'])
def cancel_request():
    user_id = session.get('current_user')
    message_id = request.form['message_id']
    if not user_id or not message_id:
        return redirect('/messages')

    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("DELETE FROM access_requests WHERE user_id = ? AND message_id = ?", (user_id, message_id))
    conn.commit()
    conn.close()
    return redirect('/messages')

@app.route('/delete_message', methods=['POST'])
def delete_message():
    user = session.get('current_user')
    message_id = request.form['message_id']

    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("SELECT submitted_by FROM messages WHERE id = ?", (message_id,))
    row = c.fetchone()
    if row and row[0] == user:
        c.execute("DELETE FROM messages WHERE id = ?", (message_id,))
        c.execute("DELETE FROM access_requests WHERE message_id = ?", (message_id,))
        conn.commit()
    conn.close()
    return '', 204


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['admin_id'] == 'srikanth130404' and request.form['password'] == '2815':
            session['admin'] = True
            return redirect('/admin')
    return render_template('login.html')

@app.route('/admin')
def admin():
    if 'admin' not in session:
        return redirect('/login')
    return render_template('admin.html')

@app.route('/admin/requests')
def view_requests():
    if 'admin' not in session:
        return redirect('/login')
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("SELECT * FROM access_requests")
    requests = c.fetchall()
    conn.close()
    return jsonify([
        {'id': r[0], 'user_id': r[1], 'message_id': r[2], 'status': r[3]}
        for r in requests
    ])

@app.route('/admin/delete_message', methods=['POST'])
def admin_delete_message():
    if 'admin' not in session:
        return '', 403
    message_id = request.form['message_id']
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("DELETE FROM messages WHERE id = ?", (message_id,))
    c.execute("DELETE FROM access_requests WHERE message_id = ?", (message_id,))
    conn.commit()
    conn.close()
    return '', 204


@app.route('/admin/grant_access', methods=['POST'])
def grant_access():
    if 'admin' not in session:
        return redirect('/login')
    request_id = request.form['request_id']
    action = request.form['action']
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("UPDATE access_requests SET status = ? WHERE id = ?", (action, request_id))
    conn.commit()
    conn.close()
    return redirect('/admin')

@app.route('/logout_user')
def logout_user():
    session.pop('current_user', None)
    session.pop('submitted', None)
    return redirect('/')

@app.route('/logout_admin')
def logout_admin():
    session.pop('admin', None)
    return redirect('/login')

@app.route('/admin/get_messages')
def get_admin_messages():
    if 'admin' not in session:
        return jsonify([])

    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("SELECT * FROM messages")
    messages = c.fetchall()
    conn.close()

    result = []
    for msg_id, encrypted_text, submitted_by, timestamp in messages:
        try:
            decrypted_text = cipher.decrypt(encrypted_text.encode()).decode()
        except:
            decrypted_text = "[Unable to decrypt]"
        result.append({
            'id': msg_id,
            'text': decrypted_text,
            'submitted_by': submitted_by,
            'timestamp': timestamp
        })
    return jsonify(result)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
