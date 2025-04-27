import socket
import os
import hashlib
import logging

# --- Setup Client Logging ---
logger = logging.getLogger(__name__)
console_handler = logging.StreamHandler()
file_handler = logging.FileHandler("client.log", mode="a", encoding="utf-8")
logger.addHandler(console_handler)
logger.addHandler(file_handler)
formatter = logging.Formatter(
    "{asctime} - {levelname} - {message}",
    style="{",
    datefmt="%Y-%m-%d %H:%M:%S",
)
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)
logger.setLevel("DEBUG")
# --- End Logging Setup ---

CHUNK_SIZE = 1024
CLIENT_DATA_PATH = "client_data"

if not os.path.exists(CLIENT_DATA_PATH):
    os.makedirs(CLIENT_DATA_PATH)

def connect_to_server():
    host = socket.gethostbyname(socket.gethostname())
    port = 6600
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        print("Connected to the server!")
        logger.info("Connected to the server.")
        return sock
    except Exception as e:
        print(f"Failed to connect: {e}")
        logger.error(f"Failed to connect to server: {e}")
        return None

def calculate_hash(file_bytes):
    hasher = hashlib.sha256()
    hasher.update(file_bytes)
    return hasher.hexdigest()

def upload_file(sock):
    filename = input("Enter the path of the file to upload: ").strip()

    if not os.path.exists(filename):
        print("File not found.")
        logger.error(f"File not found for upload: {filename}")
        return

    try:
        with open(filename, "rb") as f:
            file_data = f.read()

        file_size = len(file_data)
        file_name_only = os.path.basename(filename)
        file_hash = calculate_hash(file_data)

        sock.sendall(f"UPLOAD>{file_name_only}>{file_size}".encode())
        sock.sendall(file_data)
        sock.sendall(file_hash.encode())

        response = sock.recv(1024).decode()
        if response.startswith("Success>"):
            print(response.split(">", 1)[1])
            logger.info(f"Uploaded file: {file_name_only}")
        else:
            print("Upload failed:", response)
            logger.error(f"Upload failed for file: {file_name_only} - {response}")

    except Exception as e:
        print(f"Error during upload: {e}")
        logger.error(f"Exception during upload of {filename}: {e}")

def download_file(sock):
    file_name = input("Enter the name of the file to download: ").strip()
    try:
        request = f"DOWNLOAD>{file_name}"
        sock.sendall(request.encode())

        size_msg = sock.recv(1024).decode()
        if size_msg.startswith("Fail>"):
            print(size_msg.split(">", 1)[1])
            logger.error(f"Download failed for file: {file_name} - File not found on server.")
            return
        elif not size_msg.startswith("SIZE>"):
            print("Unexpected response from server.")
            logger.error(f"Unexpected response from server when downloading {file_name}.")
            return

        file_size = int(size_msg.split(">")[1])

        file_data = b""
        received = 0
        while received < file_size:
            chunk = sock.recv(min(CHUNK_SIZE, file_size - received))
            if not chunk:
                break
            file_data += chunk
            received += len(chunk)

        file_hash = sock.recv(64).decode()

        if calculate_hash(file_data) == file_hash:
            filepath = os.path.join(CLIENT_DATA_PATH, file_name)
            with open(filepath, "wb") as f:
                f.write(file_data)
            print(f"Downloaded and verified: {file_name}")
            logger.info(f"Downloaded and verified file: {file_name}")
        else:
            print("File integrity check failed.")
            logger.error(f"Integrity check failed for file: {file_name}")

    except Exception as e:
        print("Download failed:", e)
        logger.error(f"Exception during download of {file_name}: {e}")

def list_files(sock):
    try:
        sock.sendall("LIST".encode())
        data = sock.recv(4096).decode()
        if data.startswith("OK>"):
            print("\nFiles on server:\n" + data.split(">", 1)[1])
            logger.info("Listed available files.")
        else:
            print("Failed to list files.")
            logger.error("Failed to list files.")
    except Exception as e:
        print("Error listing files:", e)
        logger.error(f"Exception while listing files: {e}")

def show_menu():
    print("\nWhat would you like to do?")
    print("1. Upload File")
    print("2. Download File")
    print("3. List Available Files")
    print("4. Exit")

def main():
    sock = connect_to_server()
    if not sock:
        return

    while True:
        show_menu()
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            upload_file(sock)
        elif choice == "2":
            download_file(sock)
        elif choice == "3":
            list_files(sock)
        elif choice == "4":
            sock.sendall("CLOSE".encode())
            print("Goodbye!")
            logger.info("Disconnected from server.")
            break
        else:
            print("Invalid choice. Please try again.")
            logger.warning("Invalid menu choice entered by user.")

    sock.close()

if __name__ == "__main__":
    main()
