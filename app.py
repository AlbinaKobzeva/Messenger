from flask import Flask, redirect, request, render_template, session, url_for, flash, current_app
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import check_password_hash, generate_password_hash
import re
import os
import sqlite3
from os import path
app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'секретно-секретный секрет')
app.config['DB_TYPE'] = os.getenv('DB_TYPE', 'postgres')

# Подключение к базе данных
def db_connect():
    if current_app.config['DB_TYPE'] == 'postgres':
        conn = psycopg2.connect(
            host='127.0.0.1',
            database='rgz',
            user='albina',
            password='12345'
        )
        cur = conn.cursor(cursor_factory=RealDictCursor)
    else:
        dir_path = path.dirname(path.realpath(__file__))
        db_path = path.join(dir_path, "database.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
    return conn, cur


# Закрытие соединения с базой данных
def db_close(conn, cur):
    conn.commit()
    cur.close()
    conn.close()


# Главная страница
@app.route('/')
def main():
    if 'login' in session:
        return redirect(url_for('select_chat'))
    
    conn, cur = db_connect()
    cur.execute("SELECT id, login FROM users;")
    users = cur.fetchall()
    db_close(conn, cur)
    
    return render_template('main.html', users=users)


def validate_login(login):
    if not login:
        return False
    # Логин должен состоять только из латинских букв, цифр и знаков препинания
    return re.match(r'^[A-Za-z0-9_.-]+$', login) is not None

# Функция для валидации пароля
def validate_password(password):
    if not password:
        return False
    # Пароль должен состоять только из латинских букв, цифр и знаков препинания
    return re.match(r'^[A-Za-z0-9_.-]+$', password) is not None


# Регистрация пользователя
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    login = request.form.get('login')
    password = request.form.get('password')
    
    if not validate_login(login):
        return render_template('register.html', error='Логин должен состоять из латинских букв, цифр и знаков препинания')
    
    if not validate_password(password):
        return render_template('register.html', error='Пароль должен состоять из латинских букв, цифр и знаков препинания')


    if not (login and password):
        return render_template('register.html', error='Заполните все поля')
    
    conn, cur = db_connect()
    
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT login FROM users WHERE login=%s;", (login,))
    else:
        cur.execute("SELECT login FROM users WHERE login=?;", (login,))

    if cur.fetchone():
        db_close(conn, cur)
        return render_template('register.html', error='Такой пользователь уже существует')
    
    password_hash = generate_password_hash(password)

    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("INSERT INTO users (login, password, is_admin) VALUES (%s, %s, %s);", (login, password_hash, False))
    else:
        cur.execute("INSERT INTO users (login, password, is_admin) VALUES (?, ?, ?);", (login, password_hash, False))

    db_close(conn, cur)
    return render_template('success.html', login=login)


# Авторизация пользователя
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    login = request.form.get('login')
    password = request.form.get('password')
    
    if not validate_login(login):
        return render_template('login.html', error='Логин должен состоять из латинских букв, цифр и знаков препинания')
    
    if not validate_password(password):
        return render_template('login.html', error='Пароль должен состоять из латинских букв, цифр и знаков препинания')


    if not (login and password):
        return render_template('login.html', error='Заполните все поля')
    
    conn, cur = db_connect()

    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT * FROM users WHERE login=%s;", (login,))
    else:
        cur.execute("SELECT * FROM users WHERE login=?;", (login,))

    user = cur.fetchone()
    if not user or not check_password_hash(user['password'], password):
        db_close(conn, cur)
        return render_template('login.html', error='Логин и/или пароль неверны')
    
    session['login'] = user['login']
    session['is_admin'] = user['is_admin']
    session['user_id'] = user['id']
    db_close(conn, cur)
    return redirect(url_for('dashboard'))


# Выход из системы
@app.route('/logout')
def logout():
    session.pop('login', None)
    session.pop('is_admin', None)
    session.pop('user_id', None)
    return redirect(url_for('main'))


# Панель управления
@app.route('/dashboard')
def dashboard():
    if 'login' not in session:
        return redirect(url_for('main'))
    
    return redirect(url_for('select_chat'))


# Отправка сообщения
@app.route('/send_message', methods=['POST'])
def send_message():
    if 'login' not in session:
        return redirect(url_for('main'))
    
    receiver_id = request.form.get('receiver_id')
    content = request.form.get('content')
    

    if not receiver_id or not receiver_id.isdigit():
        flash('Некорректный получатель', 'error')
        return redirect(url_for('select_chat'))
    
    receiver_id = int(receiver_id)
    
    if not content:
        flash('Сообщение не может быть пустым', 'error')
        return redirect(url_for('select_chat'))
    
    conn, cur = db_connect()
    

    sender_id = session['user_id']
    
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT id FROM users WHERE id = %s;", (receiver_id,))
    else:
        cur.execute("SELECT id FROM users WHERE id = ?;", (receiver_id,))

    receiver_exists = cur.fetchone()
    if not receiver_exists:
        db_close(conn, cur)
        flash('Получатель не существует', 'error')
        return redirect(url_for('select_chat'))

    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("INSERT INTO messages (sender_id, receiver_id, content) VALUES (%s, %s, %s);",
                (sender_id, receiver_id, content))
    else:
        cur.execute("INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?);",
                (sender_id, receiver_id, content))

    conn.commit()
    
    db_close(conn, cur)
    
    flash('Сообщение отправлено', 'success')
    return redirect(url_for('chat', partner_id=receiver_id))


# Просмотр сообщений
@app.route('/messages')
def messages():
    if 'login' not in session:
        return redirect(url_for('main'))
    
    conn, cur = db_connect()
    
    user_id = session['user_id']
    
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("""
        SELECT m.id, m.content, m.created_at, u.login AS sender_login, m.sender_id, m.receiver_id
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.receiver_id = %s OR m.sender_id = %s
        ORDER BY m.created_at ASC;
        """, (user_id, user_id))
    else:
        cur.execute("""
        SELECT m.id, m.content, m.created_at, u.login AS sender_login, m.sender_id, m.receiver_id
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.receiver_id = ? OR m.sender_id = ?
        ORDER BY m.created_at ASC;
        """, (user_id, user_id))

    messages = cur.fetchall()
    db_close(conn, cur)
    
    return render_template('messages.html', messages=messages, user_id=user_id)


# Выбор пользователя для просмотра переписки
@app.route('/select_chat')
def select_chat():
    if 'login' not in session:
        return redirect(url_for('main'))
    
    conn, cur = db_connect()
    
    user_id = session['user_id']
    
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT id, login FROM users WHERE id != %s;", (user_id,))
    else:
        cur.execute("SELECT id, login FROM users WHERE id != ?;", (user_id,))

    users = cur.fetchall()
    db_close(conn, cur)
    
    return render_template('select_chat.html', users=users)


# Просмотр переписки с конкретным пользователем
@app.route('/chat/<int:partner_id>')
def chat(partner_id):
    if 'login' not in session:
        return redirect(url_for('main'))
    
    conn, cur = db_connect()
    
    user_id = session['user_id']
    
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT login FROM users WHERE id = %s;", (partner_id,))
    else:
        cur.execute("SELECT login FROM users WHERE id = ?;", (partner_id,))
    partner_login = cur.fetchone()['login']
    
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("""
            SELECT m.id, m.content, m.created_at, u.login AS sender_login, m.sender_id, m.receiver_id
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE (m.sender_id = %s AND m.receiver_id = %s) OR (m.sender_id = %s AND m.receiver_id = %s)
            ORDER BY m.created_at ASC;
        """, (user_id, partner_id, partner_id, user_id))
    else:
        cur.execute("""
            SELECT m.id, m.content, m.created_at, u.login AS sender_login, m.sender_id, m.receiver_id
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
            ORDER BY m.created_at ASC;
        """, (user_id, partner_id, partner_id, user_id))

    messages = cur.fetchall()
    db_close(conn, cur)
    
    return render_template('chat.html', messages=messages, partner_login=partner_login, user_id=user_id, partner_id=partner_id)


# Удаление сообщения
@app.route('/delete_message/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    if 'login' not in session:
        return redirect(url_for('main'))
    
    conn, cur = db_connect()
    
    user_id = session['user_id']
    
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("DELETE FROM messages WHERE id = %s AND (sender_id = %s OR receiver_id = %s);",(message_id, user_id, user_id))
    else:
        cur.execute("DELETE FROM messages WHERE id = ? AND (sender_id = ? OR receiver_id = ?);",(message_id, user_id, user_id))

    db_close(conn, cur)
    
    flash('Сообщение удалено', 'success')
    
    partner_id = request.form.get('partner_id')
    if partner_id and partner_id.isdigit():
        return redirect(url_for('chat', partner_id=partner_id))
    
    return redirect(url_for('messages'))


# Административная панель
@app.route('/admin')
def admin():
    if 'login' not in session or not session.get('is_admin'):
        return redirect(url_for('main'))
    
    conn, cur = db_connect()
    cur.execute("SELECT id, login, is_admin FROM users;")
    users = cur.fetchall()
    db_close(conn, cur)
    
    return render_template('admin.html', users=users)


# Удаление пользователя (администратор)
@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'login' not in session or not session.get('is_admin'):
        return redirect(url_for('main'))
    
    conn, cur = db_connect()

    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("DELETE FROM users WHERE id = %s;", (user_id,))
    else:
        cur.execute("DELETE FROM users WHERE id = ?;", (user_id,))
    
    db_close(conn, cur)
    
    return redirect(url_for('admin'))
    if 'login' not in session or not session.get('is_admin'):
        return redirect(url_for('main'))
    
    conn, cur = db_connect()
    
    if request.method == 'GET':

        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT id, login, is_admin FROM users WHERE id = %s;", (user_id,))
        else:
            cur.execute("SELECT id, login, is_admin FROM users WHERE id = ?;", (user_id,))

        user = cur.fetchone()
        if not user:
            db_close(conn, cur)
            flash('Пользователь не найден', 'error')
            return redirect(url_for('admin'))
        
        db_close(conn, cur)
        return render_template('edit_user.html', user=user)
    

    login = request.form.get('login')
    password = request.form.get('password')
    is_admin = request.form.get('is_admin') == 'True'
    
    if not validate_login(login):
        db_close(conn, cur)
        flash('Логин должен состоять из латинских букв, цифр и знаков препинания', 'error')
        return redirect(url_for('edit_user', user_id=user_id))
    
    if password:
        if not validate_password(password):
            db_close(conn, cur)
            flash('Пароль должен состоять из латинских букв, цифр и знаков препинания', 'error')
            return redirect(url_for('edit_user', user_id=user_id))
        password_hash = generate_password_hash(password)
    else:

        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT password FROM users WHERE id = %s;", (user_id,))
        else:
            cur.execute("SELECT password FROM users WHERE id = ?;", (user_id,))
        password_hash = cur.fetchone()['password']
    
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("""
            UPDATE users 
            SET login = %s, password = %s, is_admin = %s 
            WHERE id = %s;
        """, (login, password_hash, is_admin, user_id))
    else:
        cur.execute("""
            UPDATE users 
            SET login = ?, password = ?, is_admin = ? 
            WHERE id = ?;
        """, (login, password_hash, is_admin, user_id))

    db_close(conn, cur)
    
    flash('Пользователь успешно обновлён', 'success')
    return redirect(url_for('admin'))