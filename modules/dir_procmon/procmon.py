import os
import time
import sys
import subprocess
import threading
import psutil 
from procmon_parser import ProcmonLogsReader

from pathlib import Path
path = Path(__file__).parent.resolve()
parent = path.parents[0]
pparent = parent.parents[0]
[sys.path.append(x) for x in map(str, [path, parent, pparent]) if x not in sys.path]

from log_config import get_custom_logger
from network.utility import make_path
logger = get_custom_logger(__name__)

TIME = 20

procmon_absolute_path = make_path(path, "Procmon64.exe")
START_COMMAND = f"{procmon_absolute_path} /Minimized /Runtime "+str(TIME)+" /BackingFile out.pml"

extensions = {"doc": "WINWORD.EXE ", "excel":"EXCEL.EXE ","hwp":"HWP.EXE ","exe":"","docx":"WINWORD.EXE "}


def kill_process(ps_name):
    logger.info(f"Kill {ps_name}")

    if len(ps_name.split()) == 2:
        ps_name = ps_name.split()[0]
    ps_name = ps_name.lstrip()
    ps_name = ps_name.rstrip()
    
    print(ps_name.encode())

    for proc in psutil.process_iter():
        try:
            # 프로세스 이름, PID값 가져오기
            processName = proc.name()
            processID = proc.pid
            if processName == ps_name:
                logger.debug("Find matching process")
                parent_pid = processID  #PID
                parent = psutil.Process(parent_pid) # PID 찾기
                for child in parent.children(recursive=True):  #자식-부모 종료
                    child.kill()
                parent.kill()
     
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):   #예외처리
            pass


def pml_parse(binary_name):
    logger.info(f"Try Parsing {binary_name}")
    parse_result = []
    file_lists = os.listdir(os.getcwd())
    for files in file_lists: # 특정 용량 초과하면 out-1.pml, out-2.pml 이렇게 만들어진다.
        if ".pml" not in files:
            continue

        while True:
            try:
                f = open(files, "rb")
                pml_reader = ProcmonLogsReader(f)
                break
            except:
                f.close()

        for i in range(len(pml_reader)):
            events = next(pml_reader)         
            if binary_name in str(events.process):
                parse_result.append(events)
    
    return parse_result
    

def run_malware(f_name):
    logger.debug(f"FName: {f_name}")
    f_name_absolute = str(path.joinpath("download").joinpath(f_name))

    logger.info(f"Run Command: {f_name_absolute}")
    os.system(str(f_name_absolute))
    

def execute(f_name):
    logger.info("Trying to execute Procmon...")
    subprocess.Popen(START_COMMAND.split(), stdout=subprocess.PIPE, shell=True)
    
    t = threading.Thread(target=run_malware,args=(f_name,))
    t.start()
    
    logger.info("[*] Waiting...")
    time.sleep(TIME)
    kill_process(f_name)


def analysis_extention(name):
    si = name.split('.')[1].lower() # 파일 확장자명 뽑는다.
    ps = extensions[si] # 확장자명에 해당하는 프로세스명 뽑는다.
    return ps + name


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("add argv")
        exit(1)
        
    param = sys.argv[1]
    ps_full_name = analysis_extention(param) # wordpress.exe 파일명 <- 이렇게 return
    execute(ps_full_name)
    parse_result = pml_parse(param)

    #Save parse result 
    with open("monitoring_res.txt","wb") as f:
        for data in parse_result:
            f.write(str(data).encode())
            f.write("\n".encode())
