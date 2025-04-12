# Advanced File Sharing System

A web-based file sharing application developed for CSC 430 Computer Networks course at Lebanese American University.

## Overview

This project implements a web-based file sharing system with a modern responsive interface. Users can upload, download, and browse files through an intuitive red and blue themed UI. The system includes file integrity verification, automatic versioning for duplicate filenames, and comprehensive logging.

## Features

### Core Features
- **File Upload**: Upload files through a user-friendly web interface
- **File Download**: Browse and download available files with a single click
- **File Listing**: View all available files with details including size and modification date
- **File Versioning**: Automatic versioning of files with the same name (e.g., document_v2.pdf)
- **File Integrity**: SHA-256 hash verification for all file transfers
- **Comprehensive Logging**: All operations are logged for auditing and debugging

### Bonus Features
- **Web Interface**: Modern, responsive web interface using Flask
- **Progress Tracking**: Visual progress bar for file uploads
- **Detailed File Information**: Size, modification date, and integrity hashes

## Technology Stack

- **Backend**: Python with Flask web framework
- **Frontend**: HTML, CSS, JavaScript
- **File Integrity**: SHA-256 hashing
- **Styling**: Custom CSS with red and blue theme
- **Icons**: Font Awesome

## Setup and Installation

### Prerequisites
- Python 3.6+
- Virtual environment (venv)

### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/sprinklepancake/networks-proj.git
   cd networks-proj
   ```

2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install required packages:
   ```bash
   pip install flask
   ```

4. Run the application:
   ```bash
   python app.py
   ```

5. Access the web interface at: http://localhost:5000

### Project Structure
```
file_sharing_system/
├── app.py                 # Main Flask application
├── uploads/               # Directory to store uploaded files
├── logs/                  # Directory to store log files
└── templates/             # HTML templates
    ├── base.html          # Base template with shared layout and styles
    ├── index.html         # Landing page template
    ├── files.html         # Files listing page template
    └── upload.html        # File upload page template
```

## Usage

1. **Home Page**: Visit the landing page to get an overview of the system
2. **Browse Files**: Navigate to the Files page to see and download available files
3. **Upload Files**: Use the Upload page to add new files to the system

## Development and Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

## Future Enhancements

- User authentication and role-based access control
- Resumable downloads for interrupted transfers
- File preview capabilities for common formats
- Direct file sharing between users
- Real-time progress tracking using WebSockets

## Team Members

- [Hassan Najjar](https://github.com/sprinklepancake)
- [Reina Najjar]
- [Tala Hachem]
- [Hassan Diab]

## License

This project was developed as part of the CSC 430 Computer Networks course at Lebanese American University.

---
