import sys
from pathlib import Path
path = Path(__file__).parent.resolve()
parent = path.parents[0]
[sys.path.append(x) for x in map(str, [path, parent]) if x not in sys.path]

from processor import Processor

"""
{
    "type": "scan",
    "target_ip": "172.30.1.24",
}
"""
class Scanner(Processor):
    fields = []
    def __init__(self, cmd):
        super().__init__(cmd)
        self.check_cmd(self.fields)
    
    pass