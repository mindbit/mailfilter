import re
import sys

def send(sock, data):
    print('>>> ' + data.rstrip())
    sock.sendall(str.encode(data))

def expect(sock, code):
    pattern = re.compile('^([0-9]{3}) ')
    with sock.makefile() as file:
        while True:
            line = file.readline()
            if not line:
                print('DISCONNECTED')
                sys.exit(1)
            print('<<< ' + line.rstrip())
            match = pattern.search(line)
            if match:
                if int(match.group(1)) == code:
                    return True
                print('ERROR')
                sys.exit(1)
