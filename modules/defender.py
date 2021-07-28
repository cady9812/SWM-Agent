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
import bson

"""
{
	"type": "defense",
}
"""
class Defender(Processor):
    fields = []
    TIMEOUT = 20.0

    def __init__(self, cmd):
        super().__init__(cmd)
        logger.info(f"[defense] cmd: {cmd}")
        self.check_cmd(self.fields)
    
    def run_cmd(self):
        self.msg_list = packet.signature_sniffer(self.TIMEOUT)
        logger.info(f"[defense] Result: {self.msg_list}")

        pass

    def report(self, sock = None):
        data = {
            "pkts": self.msg_list,
            "type": "report",
            "type2": "defense",
        }

        print(data)
        try:
            sock.send(bson.dumps(data))
        except:
            raise Exception("Wrong socket")


if __name__ == '__main__':
    msg = {
        "type": "defense"
    }
    a = Defender(msg)
    a.run_cmd()
    a.report()
