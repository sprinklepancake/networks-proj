#!/usr/bin/env python3
"""
Web-based File Sharing System
CSC 430 Computer Networks - Design Project
This module implements a Flask-based web interface for file sharing.
"""
import os
import hashlib
import logging
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps

app = Flask(__name__)
app.secret_key = '1234'  

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    ''')
    conn.commit()
    conn.close()

def create_admin_user():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username='admin'")
    if not cursor.fetchone():
        password_hash = generate_password_hash('admin123')
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                      ('admin', password_hash, 'admin'))
        conn.commit()
    conn.close()

init_db()
create_admin_user()

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    if user_data:
        return User(id=user_data[0], username=user_data[1], role=user_data[3])
    return None

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Configuration
UPLOAD_FOLDER = 'uploads'
LOG_FOLDER = 'logs'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max file size

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(LOG_FOLDER, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_FOLDER, f'server_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('file_sharing_web')

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

def allowed_file(filename):
    """Check if the file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    hash_sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def get_file_list():
    """Get list of files with their details"""
    files = []
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.isfile(file_path):
            file_size = os.path.getsize(file_path)
            modified_time = datetime.fromtimestamp(os.path.getmtime(file_path))
            file_hash = calculate_hash(file_path)
            
            # Format size for display
            if file_size < 1024:
                size_str = f"{file_size} B"
            elif file_size < 1024 * 1024:
                size_str = f"{file_size/1024:.1f} KB"
            else:
                size_str = f"{file_size/(1024*1024):.1f} MB"
                
            files.append({
                'name': filename,
                'size': file_size,
                'size_formatted': size_str,
                'modified': modified_time.strftime('%Y-%m-%d %H:%M:%S'),
                'hash': file_hash
            })
    
    # Sort files by modified time (newest first)
    files.sort(key=lambda x: x['modified'], reverse=True)
    return files

@app.route('/')
def index():
    """Render the landing page"""
    return render_template('index.html')

@app.route('/files')
@login_required
def files():
    """Render the files page"""
    file_list = get_file_list()
    return render_template('files.html', files=file_list)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    """Handle file upload"""
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
            
        file = request.files['file']
        
        # If user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
            
        if file and allowed_file(file.filename):
            # Handle duplicate filenames
            filename = file.filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            if os.path.exists(file_path):
                base, ext = os.path.splitext(filename)
                version = 1
                # Find an available version number
                while os.path.exists(file_path):
                    version += 1
                    new_filename = f"{base}_v{version}{ext}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
                
                filename = os.path.basename(file_path)
                logger.info(f"File already exists, renamed to {filename}")
            
            # Save the file
            file.save(file_path)
            
            # Calculate hash
            file_hash = calculate_hash(file_path)
            
            # Log the upload
            logger.info(f"File uploaded: {filename}, size: {os.path.getsize(file_path)} bytes, hash: {file_hash}")
            
            flash(f'File "{filename}" uploaded successfully!', 'success')
            return redirect(url_for('files'))
        else:
            flash(f'File type not allowed. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}', 'error')
            return redirect(request.url)
            
    return render_template('upload.html')

@app.route('/download/<filename>')
@login_required
def download(filename):
    """Download a file"""
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(file_path):
        flash('File not found', 'error')
        return redirect(url_for('files'))
    
    # Log the download
    logger.info(f"File downloaded: {filename}, size: {os.path.getsize(file_path)} bytes")
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/api/files')
def api_files():
    """API endpoint for file list"""
    return jsonify(get_file_list())

@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error"""
    flash(f'File too large. Maximum size is {MAX_CONTENT_LENGTH/(1024*1024)} MB', 'error')
    return redirect(url_for('upload'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data and check_password_hash(user_data[2], password):
            user = User(id=user_data[0], username=user_data[1], role=user_data[3])
            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        try:
            password_hash = generate_password_hash(password)
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                          (username, password_hash))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'error')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/admin/files')
@login_required
@role_required('admin')
def admin_files():
    """Admin view of files with delete options"""
    file_list = get_file_list()
    return render_template('admin_files.html', files=file_list)


@app.route('/admin/promote/<int:user_id>')
@login_required
@role_required('admin')
def promote_user(user_id):
    """Promote a user to admin"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET role='admin' WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    flash('User promoted to admin successfully!', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/demote/<int:user_id>')
@login_required
@role_required('admin')
def demote_user(user_id):
    """Demote an admin to regular user"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET role='user' WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    flash('Admin demoted to regular user successfully!', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users')
@login_required
@role_required('admin')
def admin_users():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users ORDER BY username")
    users = cursor.fetchall()
    conn.close()
    return render_template('admin_users.html', users=users)


@app.route('/admin/delete-user/<int:user_id>')
@login_required
@role_required('admin')
def delete_user(user_id):
    """Delete a user account"""
    if current_user.id == user_id:
        flash('You cannot delete your own account', 'error')
        return redirect(url_for('admin_users'))
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/delete/<filename>')
@login_required
@role_required('admin')
def delete_file(filename):
    """Delete a file"""
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if os.path.exists(file_path):
        os.remove(file_path)
        logger.info(f"File deleted by admin: {filename}")
        flash(f'File "{filename}" deleted successfully!', 'success')
    else:
        flash('File not found', 'error')
    
    return redirect(url_for('admin_files'))

@app.route('/admin/logs')
@login_required
@role_required('admin')
def view_logs():
    """View server logs"""
    log_files = []
    for filename in os.listdir(LOG_FOLDER):
        if filename.startswith('server_'):
            file_path = os.path.join(LOG_FOLDER, filename)
            if os.path.isfile(file_path):
                modified_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                log_files.append({
                    'name': filename,
                    'modified': modified_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'size': os.path.getsize(file_path)
                })
    
    log_files.sort(key=lambda x: x['modified'], reverse=True)
    return render_template('admin_logs.html', logs=log_files)

if __name__ == '__main__':
    app.run(debug=True)
    
