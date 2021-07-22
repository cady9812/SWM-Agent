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
import requests
from multiprocessing import Process, Queue
import subprocess
import base64
from network import utility, packet

"""
{
    "type": "attack_secu",
    "download": f"http://localhost:9000/exploit/{id}",
    "target_ip": "172.30.1.24",
    "target_port": 445,
    "usage": "python <FILE> <IP>",
}
"""
class SecuAttacker(Processor):
    fields = ["download", "target_ip", "target_port", "usage"]
    signature = b"BAScope"

    def __init__(self, cmd, id):
        super().__init__(cmd, id)
        self.check_cmd(self.fields)
        self.path = str(parent) + "/tmp/ex.py"
        logger.debug(f"[secu] file: {self.path}")
        pass

    def get_packets_from_code(self):
        localhost = "127.0.0.1"
        if self.debug:
            pass

        else:
            r = requests.get(self.link)

            # 다운로드 받은 공격코드를 임시 디렉토리에 저장함
            with open(self.path, "w") as f:
                f.write(r.text)
        
        # 공격코드를 localhost 로 보낼 것이기 때문에, 
        # 1. 해당 공격 패킷을 받고, 더미 응답을 보내줄 127.0.0.1:port 서버와
        # 2. loopback 어댑터에 대한 패킷 sniffer 와
        # 3. 공격코드 실행
        # 으로 총 3가지 프로세스를 동시에 실행해야 한다.
        # 공격코드가 10초 이내에는 종료될 것이라는 믿음하에, sniffer 는 디폴트로 10초 동안만 동작한다.
        # 공격코드가 10초 이상 걸리거나, send 사이의 간격이 2초 이상이라면 코드수정이 필요하다. 
        queue = Queue()

        lo_proxy = Process(target = utility.proxy, args=(self.target_port, True, queue))
        lo_sniffer = Process(target = packet.local_sniffer, args=(self.target_port, queue))

        lo_sniffer.start()
        queue.get()     # sniff와 proxy 가 켜지기까지 기다림.

        lo_proxy.start()
        queue.get()

        # usage 에서 FILE, IP, PORT, SHELLCODE 가 필요한 경우, replace 를 통해 채워줌
        replacements = [
            ("<FILE>", self.path),
            ("<IP>", localhost),
            ("<PORT>", str(self.target_port))
        ]

        usage = self.cmd_after_replacement(self.cmd['usage'], replacements)
        logger.info(f"[secu] loopback usage: {usage}")
        subprocess.call(usage, shell=True)

        lo_proxy.join()
        lo_sniffer.join()
        msg_set = queue.get()
        
        return list(msg_set)

    def run_cmd(self, debug = False):
        self.debug = debug
        self.link = self.cmd['download']  # 공격 코드 다운로드 링크
        self.target_ip = self.cmd['target_ip']
        port = self.cmd['target_port']
        if type(port) == str:
            port = int(port)
        self.target_port = port

        # 패킷 생성
        msg_list = self.get_packets_from_code()
        logger.info(f"[secu] Create {len(msg_list)} packets: {msg_list}")

        # 모든 패킷에 시그니쳐를 붙임
        for i in range(len(msg_list)):
            msg_list[i] = msg_list[i] + self.signature

        # ip:port 로 패킷을 보냄
        packet.send_msg_with_ip(self.target_ip, self.target_port, msg_list)
        
        self.msg_list = msg_list

        return

    def report(self):
        url = self.base_url + self.report_url
        data = {
            "pkts": list(map(base64.b64encode, self.msg_list)),
            "link": self.link
        }

        logger.debug(f"[secu] requests {url}, data: {data}")
        if self.call_server(url, data) == 0:
            logger.error(f"[secu] report failed {url}, {data}")

        return


if __name__ == '__main__':
    msg = {
        "type": "attack_secu",
        "download": f"http://localhost:9000/exploit/1",
        "target_ip": "172.30.1.18",
        "target_port": 445,
        "usage": "python <FILE> <IP>",
    }

    a = SecuAttacker(msg, 1)
    a.run_cmd(debug = True)
    a.report()
