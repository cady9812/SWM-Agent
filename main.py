#!/usr/bin/env python3
import requests
from agent import Agent
from time import sleep

if __name__ == '__main__':
    A = Agent("http://0.0.0.0:9000/")
    ip_info = {"ip": A.ip}
    
    while True:
        try:
            r = requests.post(A.info_path(), json = ip_info)
            break
        except:
            sleep(3)
            pass

    A.run(r.text)
