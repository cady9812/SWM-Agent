import sys
from pathlib import Path
path = str(Path(__file__).parent.resolve())
if path not in sys.path: sys.path.append(path)

from target_attacker import TargetAttacker
from secu_attacker import SecuAttacker
from defender import Defender
from scanner import Scanner
from malware import Malware
from procmon import ProcMon

class ProcessorFactory(object):
    @classmethod
    def create(cls, cmd, id):
        cmd_type = cmd["type"]
        if cmd_type == "defense":
            return Defender(cmd)
        elif cmd_type == "scan":
            return Scanner(cmd)
        elif cmd_type == "target":
            return TargetAttacker(cmd)
        elif cmd_type == 'product_packet':
            return SecuAttacker(cmd)
        elif cmd_type == 'product_malware': # new
            return Malware(cmd)
        elif cmd_type == 'endpoint':
            return ProcMon(cmd)
        else:
            print("Not implemented")
            exit(1)
