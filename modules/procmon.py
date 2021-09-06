import sys
from pathlib import Path
path = Path(__file__).parent.resolve()
parent = path.parents[0]
[sys.path.append(x) for x in map(str, [path, parent]) if x not in sys.path]

from log_config import get_custom_logger
logger = get_custom_logger(__name__)

from processor import Processor 
from config import *
import requests
from dir_procmon.procmon import * 

"""
{
    "type" : "procmon",
    "attack_id" : 13,
    "download": url,
},
"""
class Procmon(Processor):
    FIELDS = ["attack_id", "download"]

    def __init__(self, cmd):
        super().__init__(cmd)
        self.check_cmd(self.FIELDS)
        logger.info(f"[procmon] cmd: {cmd}")

        return


    def run_cmd(self, debug=False):
        cmd = self.cmd
        if debug:
            return

        download_path = str(path.joinpath(f"dir_procmon/download/{cmd['filename']}"))
        logger.debug(f"[procmon] Download at -> {download_path}")
        try:
            r = requests.get(cmd['download'])
            encoded_binary = r.content
        except:
            logger.fatal(f"{RED}Requests to {cmd['download']} failed{END}")
            return 1

        # download and decrypt
        # KEY = ord('X')
        KEY = 0
        with open(download_path, "wb") as f:
            origin = bytearray(len(encoded_binary))
            for i in range(0, len(encoded_binary)):
                origin[i] = encoded_binary[i] ^ KEY   # TODO

            f.write(origin)
        
        # Procmon !!
        ps_full_name = analysis_extention(cmd['filename']) # wordpress.exe 파일명 <- 이렇게 return
        execute(ps_full_name)
        parse_result = pml_parse(cmd['filename'])
        with open("monitoring_res.txt","wb") as f:
            for data in parse_result:
                f.write(str(data).encode())
                f.write("\n".encode())


    def report(self, sock = None):
        data = {
            "type": "procmon_log",
            "attack_id": self.cmd["attack_id"],
        }

        logger.info(f"[procmon] data: {data}")
        self._report(sock, data)


if __name__ == '__main__':
    msg = {
        "type" : "procmon",
        "attack_id" : 13,
        "download": "http://localhost:8000/12.exe",
        "filename": "12.exe"
    }

    a = Procmon(msg)
    a.run_cmd()
    a.report()
