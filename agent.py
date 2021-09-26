from network import utility
from time import sleep

import log_config
logger = log_config.get_custom_logger(__name__)

from modules.processorFactory import ProcessorFactory
import bson, json
from multiprocessing import Process

from collections import defaultdict, deque

import config

SERVER_IP = config.SERVER_IP
TCP_PORT = config.TCP_PORT


class Agent(object):
    BUF_SIZE = 0x1000
    per_port_queue = defaultdict(deque)  # 동일한 포트면 동작하지 않도록

    def __init__(self):
        self.ip = utility.get_local_ip()
        self.id = -1

    def check_cmd(self, fields):
        for field in fields:
            assert field in self.cmd
    
    def _connect_to_server(self):
        return utility.remote(SERVER_IP, TCP_PORT)

    def connect_to_server(self):
        logger.info("[agent] Connecting...")
        self.sock = self._connect_to_server()

        # 본인이 Agent 임을 알리기 위해서
        introduce = {
        "type": "introduce",
        "detail": "agent",
        }
        utility.send_with_size(self.sock, bson.dumps(introduce))


    def _scheduler(self, cmd):
        Q = self.per_port_queue

        '''
        {
            "type": "unlock",
            "port": 445
        }
        '''
        if cmd['type'] == 'unlock':
            port = cmd['port']
            if port == 0:
                return None

            Q[port].popleft()
            if Q[port]: # 기다리는 명령어가 있다면
                logger.info("[unlock] port: ", port, Q[port][0])
                return Q[port][0]

            return None

        # 아래의 타입들은 제외하면 port 걱정없이 실행가능함.
        # 사실 agent 끼리 protocol 을 맞추는 게 더 좋은 방법이었겠지만,,
        # epoll 서버에서 defense -> attack 을 순서로 준다는 보장을 해주기에,,
        if cmd['type'] not in ['defense', 'product_packet']:
            return cmd

        port = 0
        if cmd['type'] == 'defense':
            port = cmd['port']
        elif cmd['type'] == 'attack_secu':
            port = cmd['dst_port']

        if port == 0:   # use ephermeral port
            return cmd

        # 이미 사용중인 port 라면 None 을 리턴
        result_cmd = cmd
        if Q[port]:
            logger.info("[lock] unavailable port", cmd)
            result_cmd = None
        
        Q[port].append(cmd)
        return result_cmd


    # _run 은 단일 프로세스
    def _run(self):
        logger.info("[agent] wait cmd...")
        cmd = self.sock.recv(self.BUF_SIZE)

        if not cmd:
            logger.info("[agent] TCP Server dead XXXXX")
            return True
            # exit(1)

        logger.debug(f"bson: {cmd}")
        cmd = bson.loads(cmd)
        logger.info(f"cmd: {cmd}")

        s_cmd = self._scheduler(cmd)

        if s_cmd:
            p = Process(target = self._process_cmd, args = (s_cmd, ))
            p.start()


    def _process_cmd(self, cmd):
        # json 형태의 cmd 를 처리하고,
        # 서버로 결과를 보고함
        tmp_sock = self._connect_to_server()
        utility.send_with_size(tmp_sock, bson.dumps({"type":"introduce", "detail":"tmp"}))
        # introduce 이후에 바로 report 를 보내면 두 패킷이 합쳐질 수 있음
        # 안전하게 처리하기 위해서 자기소개를 먼저하고, command 를 수행한 뒤에야 report 를 보내자
        p = ProcessorFactory.create(cmd, self.id)
        p.run_cmd()
        p.report(tmp_sock)
        tmp_sock.close()   # for report
        return


    def run(self):
        self.connect_to_server()
        while True:
            try:
                if self._run():
                    self.connect_to_server()
            except Exception as e:
                logger.error(f"Wrong Cmd: {e}")
                exit(1)
