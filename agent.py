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

class Agent(object):
    def __init__(self, server):
        self.ip = utility.get_local_ip()
        self.server = server
        self.agent_info = "agent/info"
        self.command = "command/"
        self.id = -1

    def info_path(self):
        return self.server + self.agent_info

    def run(self, response):
        self.id = json.loads(response)['agent_id']
        logger.info(f"[Agent] ID: {self.id}")
        url = self.server + self.command + str(self.id)
        cmd = ''

        # 서버에 1초마다 반복적으로 요청을 날리고, type 이라는 문자가 들어간 응답이 있는 경우에 멈춤
        # 이 작업말고는 할 일이 없기 때문에, 멀티쓰레딩으로 구현하지 않음
        while True:
            try:
                cmd = requests.get(url).text
            except:
                logger.error("[Agent] Server connection refused")
                exit(1)
            cmd = json.loads(cmd)

            if cmd['type'] != "no command":
                logger.debug(f'Command OK: {cmd}')
                break
                
            #logger.debug(f'No command: {cmd}')
            sleep(2)

        # json 형태의 cmd 를 처리하고,
        # 서버로 결과를 보고함
        p = ProcessorFactory.create(cmd, self.id)
        p.run_cmd()
        p.report()


    def set_path(self, path):
        self.path = path
