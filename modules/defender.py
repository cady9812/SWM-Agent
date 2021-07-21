import sys
from pathlib import Path
path = Path(__file__).parent.resolve()
parent = path.parents[0]
[sys.path.append(x) for x in map(str, [path, parent]) if x not in sys.path]

from processor import Processor 
from network import packet

import json
import logging
import logging.config
import pathlib
log_config = (pathlib.Path(__file__).parent.resolve().parents[0].joinpath("log_config.json"))
config = json.load(open(str(log_config)))
logging.config.dictConfig(config)
logger = logging.getLogger(__name__)

"""
{
	"type": "defense",
}
"""
class Defender(Processor):
    fields = []
    def __init__(self, cmd):
        super().__init__(cmd)
        self.check_cmd(self.fields)
    
    def run_cmd(self):
        self.msg_list = packet.signature_sniffer()
        logger.debug(f"[defense] Result: {self.msg_list}")

    def report(self):
        pass


if __name__ == '__main__':
    cmd = {
        "type": "defense"
    }
    a = Defender(cmd)
    a.run_cmd()
