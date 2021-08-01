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
from multiprocessing import Process

SERVER_IP = "0.0.0.0"
SERVER_PORT = 9000

class Agent(object):
    BUF_SIZE = 0x1000

    def __init__(self):
        self.ip = utility.get_local_ip()
        self.id = -1

    def check_cmd(self, fields):
        for field in fields:
            assert field in self.cmd

    def connect_to_server(self):
        self.sock = utility.remote(SERVER_IP, SERVER_PORT)

    # _run 은 단일 프로세스
    def _run(self):
        logger.info("[agent] wait cmd...")
        cmd = self.sock.recv(self.BUF_SIZE)

        if not cmd:
            logger.info("[agent] TCP Server dead XXXXX")
            exit(1)

        logger.debug(f"bson: {cmd}")
        cmd = bson.loads(cmd)
        logger.debug(f"dict: {cmd}")

        p = Process(target = self._process_cmd, args = (cmd, ))
        p.start()


    def _process_cmd(self, cmd):
        # json 형태의 cmd 를 처리하고,
        # 서버로 결과를 보고함
        p = ProcessorFactory.create(cmd, self.id)
        p.run_cmd()
        p.report(self.sock)
        return

    def run(self):
        logger.info("[agent] Connecting...")
        self.connect_to_server()

        while True:
            try:
                self._run()
            except Exception as e:
                logger.error(f"Wrong Cmd: {e}")

