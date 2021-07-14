import requests
from agent import Agent

if __name__ == '__main__':
    A = Agent("http://172.30.1.7:9000/")
    ip_info = { "agent": {"ip": A.ip} }
    r = requests.post(A.server, json = ip_info)
    A.set_path(r.text)
    A.run()
