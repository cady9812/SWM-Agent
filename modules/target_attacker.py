import sys
from pathlib import Path
path = Path(__file__).parent.resolve()
parent = path.parents[0]
[sys.path.append(x) for x in map(str, [path, parent]) if x not in sys.path]

"""
{
    "type": "attack_secu",
    "download": f"http://localhost:9000/exploit/{id}",
    "target_ip": "172.30.1.24",
    "target_port": 445,
    "usage": "python <FILE> <IP>",
}
"""
from processor import Processor
class TargetAttacker(Processor):
    fields = []
    def __init__(self, cmd, id):
        super().__init__(cmd, id)
        self.check_cmd(self.fields)
    
    pass