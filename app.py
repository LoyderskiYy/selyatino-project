from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
import hashlib
import os

app = Flask(__name__)
app.secret_key = os.urandom(24) # Used for session management

DATABASE = 'database.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user' NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS absences (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                fio TEXT NOT NULL,
                start_date TEXT NOT NULL,
                end_date TEXT,
                reason TEXT,
                work_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        # Add 'fio' column to existing absences table if it doesn't exist
        cursor.execute('''
            PRAGMA table_info(absences);
        ''')
        columns = cursor.fetchall()
        fio_column_exists = False
        for col in columns:
            if col['name'] == 'fio':
                fio_column_exists = True
                break
        if not fio_column_exists:
            cursor.execute('''
                ALTER TABLE absences ADD COLUMN fio TEXT;
            ''')
        db.commit()
        db.close()

# Initialize the database when the app starts
init_db()

# Add a default admin user if not exists (for initial setup)
def create_admin_user():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = 'admin'")
        admin_exists = cursor.fetchone()
        if not admin_exists:
            hashed_password = hashlib.sha256('admin'.encode()).hexdigest() # Default admin password is 'admin'
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ('admin', hashed_password, 'admin'))
            db.commit()
            print("Admin user 'admin' created with password 'admin'.")
        db.close()

create_admin_user()

@app.route('/')
def index():
    return redirect(url_for('auth')) # Redirect to authentication page

@app.route('/index') # New route for the actual index page
def show_index():
    return render_template('index.html')

@app.route('/auth')
def auth():
    return render_template('auth.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Заполните все поля!'}), 400

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    try:
        db = get_db()
        cursor = db.cursor()
        # Default role for new registrations is 'user'
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, 'user'))
        db.commit()
        db.close()
        return jsonify({'message': 'Регистрация успешна! Теперь вы можете войти.'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Пользователь с таким именем уже существует.'}), 409
    except Exception as e:
        return jsonify({'message': f'Ошибка регистрации: {str(e)}'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Заполните все поля!'}), 400

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_password))
    user = cursor.fetchone()
    db.close()

    if user:
        session['logged_in'] = True
        session['username'] = user['username']
        session['user_id'] = user['id']
        session['role'] = user['role'] # Store user role in session
        return jsonify({'message': 'Вход выполнен успешно!'}), 200
    else:
        return jsonify({'message': 'Неверное имя пользователя или пароль.'}), 401

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('auth'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('role', None)
    return redirect(url_for('index'))

@app.route('/soon')
def soon_redirect():
    return redirect(url_for('soon_page'))

@app.route('/soon.html')
def soon_page():
    if not session.get('logged_in'):
        return redirect(url_for('auth'))
    return render_template('soon.html')

@app.route('/profile')
def profile():
    if not session.get('logged_in'):
        return redirect(url_for('auth'))
    return render_template('profile.html', username=session['username'])

@app.route('/submit_absence', methods=['POST'])
def submit_absence():
    if not session.get('logged_in'):
        return jsonify({'message': 'Неавторизованный доступ!'}), 401
    
    user_id = session.get('user_id')
    data = request.get_json()
    fio = data.get('fio') # Get FIO from the request
    start_date = data.get('start_date') # Changed to snake_case
    end_date = data.get('end_date')     # Changed to snake_case
    reason = data.get('reason')
    work_type = data.get('work_type')   # Changed to snake_case
    timestamp = data.get('timestamp')

    if not all([fio, start_date, work_type, timestamp]): # Added fio to validation
        return jsonify({'message': 'Отсутствуют обязательные поля!'}), 400

    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO absences (user_id, fio, start_date, end_date, reason, work_type, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)", # Added fio column
            (user_id, fio, start_date, end_date, reason, work_type, timestamp) # Added fio value
        )
        db.commit()
        db.close()
        return jsonify({'message': 'Запись об отсутствии успешно сохранена!'}), 201
    except Exception as e:
        return jsonify({'message': f'Ошибка при сохранении записи: {str(e)}'}), 500

@app.route('/get_absences', methods=['GET'])
def get_absences():
    if not session.get('logged_in'):
        return jsonify({'message': 'Неавторизованный доступ!'}), 401

    user_id = session.get('user_id')
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM absences WHERE user_id = ? ORDER BY id DESC", (user_id,))
    absences = cursor.fetchall()
    db.close()
    
    return jsonify([dict(row) for row in absences]), 200

@app.route('/admin/users')
def admin_users():
    if not session.get('logged_in') or session.get('role') not in ['admin', 'moderator']:
        return redirect(url_for('auth'))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, role FROM users")
    users = cursor.fetchall()
    db.close()
    return render_template('admin_users.html', users=users, current_user_role=session.get('role'))

@app.route('/admin/user_absences/<int:user_id>')
def admin_user_absences(user_id):
    if not session.get('logged_in') or session.get('role') not in ['admin', 'moderator']:
        return redirect(url_for('auth'))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        return jsonify({'message': 'Пользователь не найден!'}), 404

    cursor.execute("SELECT * FROM absences WHERE user_id = ? ORDER BY id DESC", (user_id,))
    absences = cursor.fetchall()
    db.close()

    return render_template('user_absences.html', user=user, absences=absences)

@app.route('/admin/update_role', methods=['POST'])
def update_role():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return jsonify({'message': 'Недостаточно прав!'}), 403
    
    data = request.get_json()
    user_id = data.get('user_id')
    new_role = data.get('new_role')

    if not user_id or not new_role:
        return jsonify({'message': 'Отсутствуют обязательные поля!'}), 400

    if new_role not in ['user', 'moderator', 'admin']:
        return jsonify({'message': 'Недопустимая роль!'}), 400

    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        db.commit()
        db.close()
        return jsonify({'message': 'Роль пользователя успешно обновлена!'}), 200
    except Exception as e:
        return jsonify({'message': f'Ошибка при обновлении роли: {str(e)}'}), 500

if __name__ == '__main__':
    if not os.path.exists('templates'):
        os.makedirs('templates')
    if not os.path.exists('static'):
        os.makedirs('static')

    # Move existing HTML files to the 'templates' folder if they are not already there
    for filename in ['index.html', 'auth.html', 'soon.html', 'dashboard.html', 'profile.html']:
        if os.path.exists(filename) and not os.path.exists(os.path.join('templates', filename)):
            os.rename(filename, os.path.join('templates', filename))

    # Move selyatino_main.jpg to the 'static' folder if it's in the root
    if os.path.exists('selyatino_main.jpg') and not os.path.exists(os.path.join('static', 'selyatino_main.jpg')):
        os.rename('selyatino_main.jpg', os.path.join('static', 'selyatino_main.jpg'))
    app.run(debug=True, host='0.0.0.0')
