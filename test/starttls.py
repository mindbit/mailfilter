import socket
import ssl

from smtp import *

def main():
    host = 'localhost'

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.connect((host, 8025))

    expect(sock, 220)

    send(sock, 'HELO foo\r\n')
    expect(sock, 250)

    send(sock, 'STARTTLS\r\n')
    expect(sock, 220)

    # Wrap the socket with TLS
    #context = ssl.create_default_context()
    context = ssl._create_unverified_context()
    secure_sock = context.wrap_socket(sock, server_hostname=host)

    send(secure_sock, 'HELO foo\r\n')
    expect(secure_sock, 250)

    secure_sock.close()

if __name__ == "__main__":
    main()
