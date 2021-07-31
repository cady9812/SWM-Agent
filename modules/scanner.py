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
from network import scanner

"""
{
    "type": "scan",
    "dst_ip": "172.30.1.24",
}
"""
class Scanner(Processor):
    FIELDS = ["dst_ip"]

    def __init__(self, cmd):
        super().__init__(cmd)
        self.check_cmd(self.FIELDS)
        logger.info(f"[scan] cmd: {cmd}")

        return

    def run_cmd(self):
        target_ip = self.cmd["target_ip"]
        # windows 같은 경우 디폴트로 ping 이 먹히지 않기 때문에, -Pn 옵션을 사용
        res = scanner.nmap_target(target_ip, "-A", "-Pn")
        self.parsed_res = scanner.nmap_parser(res)

        logger.info(f"[scan] scan result: {self.parsed_res}")


    def report(self, sock):
        data = {
            "type": "scan",
            "ports": self.parsed_res,
        }

        logger.info(f"[scan] data: {data}")
        self._report(sock, data)


if __name__ == '__main__':
    msg = {
        "type": "scan",
        "target_ip": "0.0.0.0",
    }
    a = Scanner(msg)
    a.run_cmd()
    a.report()
