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
    fields = []
    def __init__(self, cmd, id):
        super().__init__(cmd, id)
        self.check_cmd(self.fields)

    def run_cmd(self):
        pass

    def report(self):
        url = self.base_url + self.report_url
        data = {

        }
