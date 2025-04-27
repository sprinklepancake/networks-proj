import os
import socket
import threading
import hashlib
import logging

IP = socket.gethostbyname(socket.gethostname())
PORT = 6600
ADDR = (IP, PORT)
SIZE = 1024
SERVER_DATA_PATH = "server_data"

# setting up logging
logger = logging.getLogger(__name__)
console_handler = logging.StreamHandler()
file_handler = logging.FileHandler("server.log", mode="a", encoding="utf-8")
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

if not os.path.exists(SERVER_DATA_PATH):
    os.makedirs(SERVER_DATA_PATH)

def calculateHash(file_bytes):
    hasher = hashlib.sha256()
    hasher.update(file_bytes)
    return hasher.hexdigest()

def verifyIntegrity(file_bytes, received_hash):
    return calculateHash(file_bytes) == received_hash

def handle_client(connectionSock, addr):
    #print(f"[NEW CONNECTION] {addr} connected.")
    logger.info(f"[NEW CONNECTION] {addr} connected.")

    while True:
        try:
            data = connectionSock.recv(SIZE).decode()
            if not data:
                break

            parts = data.split(">")
            request = parts[0]

            if request == "UPLOAD":
                file_name = parts[1]
                file_size = int(parts[2])

                # receive file
                file_data = b""
                received = 0
                while received < file_size:
                    chunk = connectionSock.recv(min(SIZE, file_size - received))
                    if not chunk:
                        break
                    file_data += chunk
                    received += len(chunk)

                # receive hash
                file_hash = connectionSock.recv(64).decode()

                #print(f"[UPLOAD] Received {received} bytes for {file_name}")
                #print(f"[UPLOAD] Received hash: {file_hash}")
                logger.debug(f"[UPLOAD] Received {received} bytes for {file_name}")
                logger.debug(f"[UPLOAD] Received hash: {file_hash}")

                # check for file integrity 
                if verifyIntegrity(file_data, file_hash):
                    root, ext = os.path.splitext(file_name)
                    file_name = f"{root}_v{1}{ext}"
                    filepath = os.path.join(SERVER_DATA_PATH, file_name)
                    # check if the file already exists  
                    if (os.path.isfile(filepath)):
                        # for each version number, check if that version exists. if not, assign the version number to the new file
                        for i in range(2, 1000):
                            new_file = f"{root}_v{i}{ext}"
                            filepath = os.path.join(SERVER_DATA_PATH, new_file)
                            if not os.path.isfile(filepath):
                                with open(filepath, "wb") as f:
                                    f.write(file_data)
                                break
                    else: # file does not exist
                        with open(filepath, "wb") as f:
                            f.write(file_data)

                    connectionSock.send("Success>File uploaded.".encode())
                    logger.info("File was uploaded successfully.")
                else:
                    connectionSock.send("Fail>File failed to transfer safely.".encode())
                    logger.warning("File failed to transfer safely.")

            elif request == "LIST":
                files = os.listdir(SERVER_DATA_PATH)
                send_data = "OK>"
                if not files:
                    send_data += "There are no files"
                else:
                    send_data += "\n".join(files)
                connectionSock.send(send_data.encode())
                logger.info("List of files was sent.")

            elif request == "DOWNLOAD":
                file_name = parts[1]
                root, ext = os.path.splitext(file_name)
                file_name = f"{root}_v{1}{ext}"
                filepath = os.path.join(SERVER_DATA_PATH, file_name)

                # check if the file exists on the server
                if (not os.path.exists(filepath)):
                    connectionSock.send("Fail>File not found.".encode())
                    logger.warning("File not found.")
                else:
                    # a version 1 exists, so now we check for the latest version
                    i = 1
                    while (os.path.exists(filepath)):
                        i += 1
                        file_name = f"{root}_v{i}{ext}"
                        filepath = os.path.join(SERVER_DATA_PATH, file_name)
                        
                    i -= 1 # number of the latest version 
                    file_name = f"{root}_v{i}{ext}"
                    filepath = os.path.join(SERVER_DATA_PATH, file_name)
                    with open(filepath, "rb") as f:
                        file_data = f.read()
                    file_size = len(file_data)

                    # sends file size, file, and its hash
                    connectionSock.sendall(f"SIZE>{file_size}".encode())
                    connectionSock.sendall(file_data)
                    connectionSock.sendall(calculateHash(file_data).encode())
                    logger.info("File and its hash was sent.")
                
                


            elif request == "CLOSE":
                #print(f"[DISCONNECT] {addr} disconnected.")
                logger.info(f"[DISCONNECT] {addr} disconnected.")
                break

        except Exception as e:
            #print(f"⚠️ Error with client {addr}: {e}")
            logger.error(f"Error with client {addr}: {e}")
            break

    connectionSock.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    server.listen()
    #print(f"[STARTED] Server running on {IP}:{PORT}")
    logger.info(f"[STARTED] Server running on {IP}:{PORT}")

    while True:
        client_socket, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        thread.start()

if __name__ == "__main__":
    main()
