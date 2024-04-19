import socket
import re
import base64
import sys

def send(sock, data):
    print('>>> ' + data.rstrip())
    sock.sendall(str.encode(data))

def expect(sock, code):
    pattern = re.compile('^([0-9]{3}) ')
    with sock.makefile() as file:
        while True:
            line = file.readline()
            print('<<< ' + line.rstrip())
            match = pattern.search(line)
            if match:
                if int(match.group(1)) == code:
                    return True
                print('ERROR')
                sys.exit(1)

def b64enc(s):
    return base64.b64encode(str.encode(s)).decode()

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 8025))

    expect(sock, 220)

    send(sock, 'HELO foo\r\n')
    expect(sock, 250)

    if False:
        send(sock, 'AUTH LOGIN\r\n')
        expect(sock, 334)

        send(sock, b64enc('user') + '\r\n')
        expect(sock, 334)

        send(sock, b64enc('1234') + '\r\n')
        expect(sock, 235)

    send(sock, 'MAIL FROM:<rrendec@mindbit.ro>\r\n')
    expect(sock, 250)

    send(sock, 'RCPT TO:<rrendec@localhost>\r\n')
    expect(sock, 250)

    send(sock, 'DATA\r\n')
    expect(sock, 354)

    for line in sys.stdin:
        if line.startswith('.'):
            line = '.' + line
        send(sock, line.rstrip() + '\r\n')
    send(sock, '.\r\n')
    expect(sock, 250)

    send(sock, 'QUIT\r\n')
    expect(sock, 221)

    print('SUCCESS')

if __name__ == "__main__":
    main()
