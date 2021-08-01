import sys
from pathlib import Path
path = Path(__file__).parent.resolve()
parent = path.parents[0]
[sys.path.append(x) for x in map(str, [path, parent]) if x not in sys.path]

import json
import logging
import logging.config
import pathlib
log_config = (pathlib.Path(__file__).parent.resolve().parents[0].joinpath("log_config.json"))
config = json.load(open(str(log_config)))
logging.config.dictConfig(config)
logger = logging.getLogger(__name__)

from processor import Processor
from multiprocessing import Process, Queue
import subprocess, os, socket
import bson
from network import utility, packet

"""
{
    "type" : "attack_secu", # 보안장비
    "malware": False,
    "dst_ip" : "y.y.y.y",
    "dst_port": 445,
    "download": f"http://localhost:9000/exploit/{id}",
    "file_size": 1000,
    "usage": "python <FILE> <IP>",
    "attack_id" : 13
},
"""
class SecuAttacker(Processor):
    FIELDS = ["malware", "dst_ip", "dst_port", "file_size", 
              "download","usage", "attack_id"]

    def __init__(self, cmd):
        super().__init__(cmd)
        self.check_cmd(self.FIELDS)
        attack_id = self.cmd["attack_id"]
        self.path = str(parent) + f"/tmp/ex{attack_id}.py"
        logger.debug(f"[secu] file: {self.path}")

        return


    def get_packets_from_code(self):
        localhost = "127.0.0.1"
        if self.debug:
            pass

        else:
            self.xor_download(self.link, self.path)
            assert os.path.getsize(self.path) == self.cmd['file_size']

        # 공격코드를 localhost 로 보낼 것이기 때문에, 
        # 1. 해당 공격 패킷을 받고, 더미 응답을 보내줄 127.0.0.1:port 서버와
        # 2. loopback 어댑터에 대한 패킷 sniffer 와
        # 3. 공격코드 실행
        # 으로 총 3가지 프로세스를 동시에 실행해야 한다.
        # 공격코드가 10초 이내에는 종료될 것이라는 믿음하에, sniffer 는 디폴트로 10초 동안만 동작한다.
        # 공격코드가 10초 이상 걸리거나, send 사이의 간격이 2초 이상이라면 코드수정이 필요하다. 
        queue1 = Queue()
        queue2 = Queue()

        port = self.target_port
        lo_proxy = Process(target = utility.random_port_proxy, args=(port, True, queue1))
        lo_proxy.start()
        port = queue1.get()
        self.target_port = port

        lo_sniffer = Process(target = packet.local_sniffer, args=(port, queue2))
        lo_sniffer.start()
        queue2.get()     # sniff와 proxy 가 켜지기까지 기다림.

        if self.cmd['malware']:
            # random port 로 연 echo server 가 있기 때문에, 그곳으로 tcp 연결을 수행.
            tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tmp.connect((localhost, port))
            logger.info(f"[secu][malware] {localhost}:{port}")

            # 매우 큰 사이즈의 악성코드라도 잘 보낼 수 있도록 os.write 을 사용함.
            # reference: https://stackoverflow.com/questions/8679547/send-large-files-over-socket-in-c?rq=1
            os.write(tmp.fileno(), open(self.path, "rb").read())

        else:
            # usage 에서 FILE, IP, PORT, SHELLCODE 가 필요한 경우, replace 를 통해 채워줌
            replacements = [
                ("<FILE>", self.path),
                ("<IP>", localhost),
                ("<PORT>", str(port))
            ]

            usage = self.cmd_after_replacement(self.cmd['usage'], replacements)
            logger.info(f"[secu] loopback usage: {usage}")
            
            subprocess.call(usage, shell=True)

        lo_proxy.join()
        lo_sniffer.join()
        msg_set = queue2.get()

        return list(msg_set)


    def run_cmd(self, debug = False):
        self.debug = debug

        self.link = self.cmd['download']  # 공격 코드 다운로드 링크
        self.target_ip = self.cmd['dst_ip']
        port = self.cmd['dst_port']
        if isinstance(port, str):
            port = int(port)
        self.target_port = port

        msg_list = []
        sig_msg_list = []

        if self.cmd['malware']:
            self.target_port = 0

        msg_list = self.get_packets_from_code()
        logger.info(f"[secu] Create {len(msg_list)} packets: {msg_list}")

        # 모든 패킷에 시그니쳐를 붙임
        signature = f"BAScope{self.cmd['attack_id']}"
        signature_b = signature.encode()

        for i in range(len(msg_list)):
            sig_msg_list.append( msg_list[i] + signature_b )

        # ip:port 로 패킷을 보냄
        packet.send_msg_with_ip(self.target_ip, self.target_port, sig_msg_list)

        self.msg_list = msg_list

        return


    def report(self, sock = None):
        data = {
            "pkts": self.msg_list,
            "type": "report",
            "who": "send",
            "attack_id": self.cmd['attack_id'],
        }

        logger.info(f"[secu] data: {data}")
        self._report(sock, data)


if __name__ == '__main__':
    msg = {
        "type" : "attack_secu", # 보안장비
        "malware": True,
        "dst_ip" : "127.0.0.1",
        "dst_port": 445,
        "download": f"http://localhost:9000/download/1",
        "file_size": 4656,
        "usage": "python <FILE> <IP>",
        "attack_id" : 1
    }

    a = SecuAttacker(msg)
    # a.run_cmd(debug = True)
    a.run_cmd()
    a.report()

