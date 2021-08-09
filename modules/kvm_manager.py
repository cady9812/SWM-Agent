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
        logger.info(f"[snapshot - list {domain}] {result}")
        return result


    def create_snapshot(self, domain, new_name):
        result = self.localhost.snapshot.create_as(domain, new_name)
        logger.info(f"[snapshot - create {domain} {new_name}] {result}")
        return result


    def delete_snapshot(self, domain, snapshot_name):
        result = self.localhost.snapshot.delete(domain, snapshot_name)
        logger.info(f"[snapshot - delete {domain} {snapshot_name}] {result}")
        return result


    def revert_snapshot(self, domain, snapshot_name):
        result = self.localhost.snapshot.revert(domain, snapshot_name)
        logger.info(f"[snapshot - revert {domain} {snapshot_name}] {result}")
        return result


    def start_vm(self, domain):
        result = self.localhost.domain.start(domain)
        logger.info(f"[vm - start {domain}] {result}")
        return result

    
    def shutdown_vm(self, domain):
        # shutdown 을 쓰면 강제로는 안꺼져서 destroy 사용
        result = self.localhost.domain.destroy(domain)
        logger.info(f"[vm - shutdown {domain}] {result}")
        return result


    def state_vm(self, domain):
        result = self.localhost.domain.state(domain)
        logger.info(f"[vm - state {domain}] {result}")
        return result

if __name__ == '__main__':
    msg = {
        "type" : "kvm", # 보안장비
    }
    k = KvmManager(msg)
    k.start_vm('win10')
    from time import sleep
    sleep(20)
    k.shutdown_vm('win10')
    k.state_vm('win10')
