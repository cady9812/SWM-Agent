from network import utility
import json
from time import sleep
import requests

import logging
import logging.config
config = json.load(open('log_config.json'))
logging.config.dictConfig(config)
logger = logging.getLogger(__name__)

from modules.processorFactory import ProcessorFactory
import bson

SERVER_IP = "0.0.0.0"
SERVER_PORT = 9000

class Agent(object):
    BUF_SIZE = 0x1000

    def __init__(self):
        self.ip = utility.get_local_ip()
        self.id = -1

    def connect_to_server(self):
        self.sock = utility.remote(SERVER_IP, SERVER_PORT)

    def run(self):
        self.connect_to_server()
        introduce = {
            "type": "agent",
            "ip": self.ip,
        }

        logger.info(introduce)
        self.sock.send(bson.dumps(introduce))
        cmd = self.sock.recv(self.BUF_SIZE)
        cmd = bson.loads(cmd)
        logger.info(cmd)

        # json 형태의 cmd 를 처리하고,
        # 서버로 결과를 보고함
        p = ProcessorFactory.create(cmd, self.id)
        p.run_cmd()
        p.report(self.sock)

