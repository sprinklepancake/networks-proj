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

app = Flask(__name__)
app.secret_key = 'my_secret_key_trial'

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
def files():
    """Render the files page"""
    file_list = get_file_list()
    return render_template('files.html', files=file_list)

@app.route('/upload', methods=['GET', 'POST'])
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

if __name__ == '__main__':
    app.run(debug=True)