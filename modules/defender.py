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
from network import packet

"""
{
						"type" : "defense",
						"src_ip" : "x.x.x.x", # src_ip에게 이 명령을 보내라
						"attack_id" : 13,
},
"""
class Defender(Processor):
    TIMEOUT = 20.0
    FIELDS = ["attack_id", "port"]

    def __init__(self, cmd):
        super().__init__(cmd)
        self.check_cmd(self.FIELDS)
        logger.info(f"[defense] cmd: {cmd}")

        return


    def run_cmd(self):
        attack_id = self.cmd['attack_id']
        self.msg_list = packet.signature_sniffer(self.TIMEOUT, signature = f"BAScope{attack_id}")
        logger.info(f"[defense] Result: {self.msg_list}") 


    def report(self, sock = None):
        data = {
            "pkts": self.msg_list,
            "who": "recv",
            "type": "report",
            "attack_id": self.cmd["attack_id"],
        }

        logger.info(f"[defense] data: {data}")
        self._report(sock, data)


if __name__ == '__main__':
    msg = {
        "type" : "defense",
        "attack_id" : 1,
        "port": 445,
    }
    a = Defender(msg)
    a.run_cmd()
    a.report()
