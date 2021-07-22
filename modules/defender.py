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
	"type": "defense",
}
"""
class Defender(Processor):
    fields = []
    def __init__(self, cmd, id):
        super().__init__(cmd, id)
        logger.info(f"[defense] cmd: {cmd}, id: {id}")
        self.check_cmd(self.fields)
    
    def run_cmd(self):
        self.msg_list = packet.signature_sniffer(1)
        logger.info(f"[defense] Result: {self.msg_list}")

        pass

    def report(self):
        url = self.base_url + self.report_url
        data = {
            "pkts": self.msg_list
        }

        logger.debug(f"[defense] requests {url}, data: {data}")
        if self.call_server(url, data) == 0:
            logger.error(f"[defense] report failed {url}, {data}")

        pass


if __name__ == '__main__':
    msg = {
        "type": "defense"
    }
    a = Defender(msg, 1)
    a.run_cmd()
    a.report()
