#!/usr/bin/env python3
import requests
from agent import Agent

if __name__ == '__main__':
    A = Agent("http://192.168.0.221:5000/")
    ip_info = {"ip": A.ip}
    r = requests.post(A.info_path(), json = ip_info)
    A.run(r.text)
