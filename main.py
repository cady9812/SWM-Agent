import requests
from agent import Agent

if __name__ == '__main__':
    A = Agent("http://0.0.0.0:9000/")
    ip_info = {"ip": A.ip}
    r = requests.post(A.info_path(), json = ip_info)
    A.run(r.text)
