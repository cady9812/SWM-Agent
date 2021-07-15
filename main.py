import requests
from agent import Agent

if __name__ == '__main__':
    A = Agent("http://0.0.0.0:9000/")
    ip_info = { "agent": {"ip": A.ip} }
    r = requests.post(A.server, json = ip_info)
    A.set_path(r.text)
    A.run()
