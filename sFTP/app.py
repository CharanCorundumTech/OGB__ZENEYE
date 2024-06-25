import paramiko
import os

def handle_upload(sftp, filename, file_contents):
    remote_directory = 'D:/OGBDATA'
    remote_path = remote_directory + '/' + filename
    with sftp.file(remote_path, 'w') as file:
        file.write(file_contents)
    print(f"File '{filename}' uploaded successfully.")


def sftp_server():
    hostname = '10.40.16.190'
    port = 22
    username = 'ogbuser'
    password = 'Technology@2022'

    transport = paramiko.Transport((hostname, port))
    transport.connect(username=username, password=password)
    sftp = paramiko.SFTPClient.from_transport(transport)
    print(sftp)

    while True:
        print("Waiting for client to connect...")
        # Accept a connection from a client
        client_transport, client_address = transport.accept()
        print(f"Connection established with {client_address}")
        client_sftp = paramiko.SFTPClient.from_transport(client_transport)

        # Receive file from client
        for filename in client_sftp.listdir():
            with client_sftp.file(filename, 'r') as file:
                file_contents = file.read()
            handle_upload(sftp, filename, file_contents)

if __name__ == "__main__":
    sftp_server()