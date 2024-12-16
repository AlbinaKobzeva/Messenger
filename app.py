from flask import Flask, redirect, request, render_template, session, url_for, flash
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = 'секретно-секретный секрет'

# Подключение к базе данных
def db_connect():
    conn = psycopg2.connect(
        host='127.0.0.1',
        database='rgz',
        user='albina',
        password='12345'
    )
    cur = conn.cursor(cursor_factory=RealDictCursor)
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


# Регистрация пользователя
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    login = request.form.get('login')
    password = request.form.get('password')
    if not (login and password):
        return render_template('register.html', error='Заполните все поля')
    
    conn, cur = db_connect()
    cur.execute("SELECT login FROM users WHERE login=%s;", (login,))
    if cur.fetchone():
        db_close(conn, cur)
        return render_template('register.html', error='Такой пользователь уже существует')
    
    password_hash = generate_password_hash(password)
    cur.execute("INSERT INTO users (login, password, is_admin) VALUES (%s, %s, %s);", (login, password_hash, False))
    db_close(conn, cur)
    return render_template('success.html', login=login)


# Авторизация пользователя
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    login = request.form.get('login')
    password = request.form.get('password')
    if not (login and password):
        return render_template('login.html', error='Заполните все поля')
    
    conn, cur = db_connect()
    cur.execute("SELECT * FROM users WHERE login=%s;", (login,))
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
    

    cur.execute("SELECT id FROM users WHERE id = %s;", (receiver_id,))
    receiver_exists = cur.fetchone()
    if not receiver_exists:
        db_close(conn, cur)
        flash('Получатель не существует', 'error')
        return redirect(url_for('select_chat'))

    cur.execute("INSERT INTO messages (sender_id, receiver_id, content) VALUES (%s, %s, %s);",
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
    
    cur.execute("""
        SELECT m.id, m.content, m.created_at, u.login AS sender_login, m.sender_id, m.receiver_id
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.receiver_id = %s OR m.sender_id = %s
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
    
    cur.execute("SELECT id, login FROM users WHERE id != %s;", (user_id,))
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
    
    cur.execute("SELECT login FROM users WHERE id = %s;", (partner_id,))
    partner_login = cur.fetchone()['login']
    
    cur.execute("""
        SELECT m.id, m.content, m.created_at, u.login AS sender_login, m.sender_id, m.receiver_id
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = %s AND m.receiver_id = %s) OR (m.sender_id = %s AND m.receiver_id = %s)
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
    
    cur.execute("DELETE FROM messages WHERE id = %s AND (sender_id = %s OR receiver_id = %s);",
                (message_id, user_id, user_id))
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
    cur.execute("DELETE FROM users WHERE id = %s;", (user_id,))
    db_close(conn, cur)
    
    return redirect(url_for('admin'))