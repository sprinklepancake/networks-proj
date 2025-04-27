import socket
import os
import hashlib

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
        return sock
    except Exception as e:
        print(f"Failed to connect: {e}")
        return None

def calculate_hash(file_bytes):
    hasher = hashlib.sha256()
    hasher.update(file_bytes)
    return hasher.hexdigest()

def upload_file(sock):
    filename = input("Enter the path of the file to upload: ").strip()

    if not os.path.exists(filename):
        print("File not found.")
        return

    try:
        with open(filename, "rb") as f:
            file_data = f.read()

        file_size = len(file_data)
        file_name_only = os.path.basename(filename)
        file_hash = calculate_hash(file_data)

        # Send upload request
        sock.sendall(f"UPLOAD>{file_name_only}>{file_size}".encode())

        # Send file data
        sock.sendall(file_data)

        # Send hash (64 bytes)
        sock.sendall(file_hash.encode())

        # Get response
        response = sock.recv(1024).decode()
        if response.startswith("Success>"):
            print("Upload complete and verified.")
        else:
            print("Upload failed:", response)

    except Exception as e:
        print(f"Error during upload: {e}")

def download_file(sock):
    file_name = input("Enter the name of the file to download: ").strip()
    try:
        request = f"DOWNLOAD>{file_name}"
        sock.sendall(request.encode())

        # Step 1: receive file size
        size_msg = sock.recv(1024).decode()
        if size_msg.startswith("Fail>"):
            print(size_msg)
            return
        elif not size_msg.startswith("SIZE>"):
            print("Unexpected response from server.")
            return

        file_size = int(size_msg.split(">")[1])

        # Step 2: receive file content
        file_data = b""
        received = 0
        while received < file_size:
            chunk = sock.recv(min(CHUNK_SIZE, file_size - received))
            if not chunk:
                break
            file_data += chunk
            received += len(chunk)

        # Step 3: receive hash
        file_hash = sock.recv(64).decode()

        if calculate_hash(file_data) == file_hash:
            filepath = os.path.join(CLIENT_DATA_PATH, file_name)
            with open(filepath, "wb") as f:
                f.write(file_data)
            print(f"Downloaded and verified: {file_name}")
        else:
            print("File integrity check failed.")

    except Exception as e:
        print("Download failed:", e)


def list_files(sock):
    try:
        sock.sendall("LIST".encode())
        data = sock.recv(4096).decode()
        if data.startswith("OK>"):
            print("\nFiles on server:\n" + data.split(">", 1)[1])
        else:
            print("Failed to list files.")
    except Exception as e:
        print("Error listing files:", e)

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
            break
        else:
            print("Invalid choice. Please try again.")

    sock.close()

if __name__ == "__main__":
    main()
