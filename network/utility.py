import socket
import struct
import time

def recv_with_size(sock, timeout = 10.0):
    sock.settimeout(timeout) # recv timeout for 5s

    try:
        size = sock.recv(4)
    except socket.timeout:
        return b''

    total_length = struct.unpack(">i", size)[0]
    received = b''

    while len(received) < total_length:
        data = ''
        try:
            data = sock.recv(total_length)
        except socket.timeout:
            return received
        received += data

    return received

def send_with_size(sock, payload):
    sock.send(struct.pack('>i', len(payload)))
    sock.send(payload.encode())

def open_server(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((ip, port))
    sock.listen(0)
    return sock

def remote(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            s.connect((ip, port))
            break
        except ConnectionRefusedError:
            time.sleep(0.1)
            pass

    return s

def get_local_ip(server_ip="8.8.8.8"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((server_ip, 0))
    ip = s.getsockname()[0]
    s.close()
    return ip

if __name__ == "__main__":
    pass
