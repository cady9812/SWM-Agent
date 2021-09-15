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
from dir_procmon.procmon import execute, analysis_extention, pml_parse
from network.utility import make_path, current_time

"""
{
    "type": "endpoint",
    "download": "다운로드링크(암호화된 api)",
    "filename": "12.exe", // 한글이면 qweqwe.hwp 등등.. 확장자가 중요함
    "attack_id": 12,
}
"""
class ProcMon(Processor):
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

        download_path = make_path(path, f"dir_procmon/download/{cmd['filename']}")
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
        report_name = f"{current_time()}-{cmd['filename']}.log"
        report_path = str(path.joinpath("./dir_procmon/report/").joinpath(report_name))
        logger.debug(f"Report Path: {report_path}")
        result = "\n".join(map(str, parse_result))
        with open(report_path, "wb") as f:
            f.write(result.encode())
        
        self.result = result
        return


    def report(self, sock = None):
        data = {
            "type": "procmon",
            "attack_id": self.cmd["attack_id"],
            "log": self.result,
            "ticket": self.ticket,
        }

        logger.info(f"[procmon] attack_id: {data['attack_id']}")
        logger.info(f"[procmon] ticket: {self.data['ticket']}")
        logger.info(f"[procmon] log length: {len(data['log'])}")
        self._report(sock, data)


if __name__ == '__main__':
    msg = {
        "type" : "endpoint",
        "attack_id" : 13,
        "download": "http://172.30.1.14:8000/12.exe",
        "filename": "12.exe",
        "ticket": 3,
    }

    a = ProcMon(msg)
    a.run_cmd()
    a.report()
