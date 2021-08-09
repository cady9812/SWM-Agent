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
import kvm
from unix import Local, Remote, UnixError
from unix.linux import Linux



class KvmManager(Processor):
    def __init__(self, cmd):
        super().__init__(cmd)
        self.localhost = kvm.Hypervisor(Linux(Local()))
        return


    def run_cmd(self, cmd):
        return


    def report(self):
        pass


    def list_snapshots(self, domain):
        result = self.localhost.list_snapshots(domain)
        print(result)
        return


    def revert_snapshot(self, domain, snapshot_name):
        result = self.localhost.snapshot.revert(domain, snapshot_name)
        return result


if __name__ == '__main__':
    msg = {
        "type" : "kvm", # 보안장비
    }
    kmanager = KvmManager(msg)
    kmanager.list_snapshots('win10')
