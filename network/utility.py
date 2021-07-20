import socket
import struct
import time

import json
import logging
import logging.config
import pathlib
log_config = (pathlib.Path(__file__).parent.resolve().parents[0].joinpath("log_config.json"))
config = json.load(open(str(log_config)))
logging.config.dictConfig(config)
logger = logging.getLogger(__name__)

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
    logger.info(f"[Open Server] IP: {ip}, Port: {port}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if type(port) == str:
        logger.debug("type(port) is str, converting to int")
        port = int(port)

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


def proxy(port, agent = False, queue = None):
    logger.info(f"Open echo server with port:{port}")

    loopback = "127.0.0.1"
    s = open_server(loopback, port)
    if agent:
        queue.put("OK")
    c, _ = s.accept()
    c.settimeout(2.0)

    try:
        while True:
            msg = c.recv(50000)
            logger.debug(f"loopback gets msg: {msg}")
            c.send(b"X" * 5000)     # 너무 많은 데이터를 보내면 sniff 에서 중요한 패킷을 놓칠 수 있음.
    except socket.timeout:
        pass
    except: # ConnectionResetError
        pass

    c.close()

if __name__ == "__main__":
    proxy(445)
    pass
