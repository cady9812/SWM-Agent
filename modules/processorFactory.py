import sys
from pathlib import Path
path = str(Path(__file__).parent.resolve())
if path not in sys.path: sys.path.append(path)

from target_attacker import TargetAttacker
from secu_attacker import SecuAttacker
from defender import Defender
from scanner import Scanner

class ProcessorFactory(object):
    @classmethod
    def create(cls, cmd, id):
        cmd_type = cmd["type"]
        if cmd_type == "defense":
            return Defender(cmd, id)
        elif cmd_type == "scan":
            return Scanner(cmd, id)
        elif cmd_type == "attack_target":
            return TargetAttacker(cmd, id)
        elif cmd_type == 'attack_secu':
            return SecuAttacker(cmd, id)
        else:
            print("Not implemented")
            exit(1)
