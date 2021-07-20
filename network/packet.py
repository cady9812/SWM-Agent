from scapy.all import *
from ordered_set import OrderedSet as oSet

import json
import logging
import logging.config
import pathlib
log_config = (pathlib.Path(__file__).parent.resolve().parents[0].joinpath("log_config.json"))
config = json.load(open(str(log_config)))
logging.config.dictConfig(config)
logger = logging.getLogger(__name__)

loopback = "127.0.0.1"

# timeout (=10.0s) 동안 localhost -> localhost:port 로 향하는 패킷을 감청한다.
# 그러한 통신이 여러 개 발생하지 않을 것이라는 가정하여, 프로세스 필터링은 진행하지 않았다.
# TCP/UDP 계층 이후의 내용이 존재하는 패킷에 대하여, 그 부분을 분리하여 리턴해준다.
# TCP 의 경우 패킷을 받을 상대가 없어서 동일한 패킷을 여러 번 보내는 경우가 있기 때문에, set으로 중복을 제거함
def local_sniffer(port, queue, timeout = 10.0):
    def checker(pkt):
        if pkt[IP].src == loopback and pkt[IP].dst == loopback:
            if pkt.dport == port:
                return True
        return False

    def start():
        queue.put("START")

    result = sniff(
        lfilter = checker,
        timeout = 10.0,
        iface = get_loopback_iface_name(),  # iface 를 lo로 안주면 loopback에서 오가는 패킷들을 아예 잡지 못하는 것 같음.
        started_callback = start,
    )

    # 패킷의 순서를 보존하기 위해서 ordered_set 을 사용.
    # 그럴 것 같지는 않지만, 보안 장비가 패킷 사이의 
    msg_set = oSet()
    for pkt in result:
        # Ether / IP / TCP|UDP / Data
        # 만약 Ether 나 IP 등이 없는 패킷이 있다면 미탐이 발생할 수 있다.
        if 4 <= len(pkt.layers()):
            # pkt.show()
            msg = bytes(pkt[3])
            msg_set.add(msg)

    # 디버깅 - 파이썬 인터프리터와 상호작용
    # import code
    # code.interact(local = locals())
    queue.put(msg_set)
    return

# signature 로 끝나는 패킷만 캡쳐하여 리턴함
def signature_sniffer(signature = "BAScope"):
    b_signature = signature.encode()

    signature_checker = lambda pkt: bytes(pkt).endswith(b_signature)

    # 공격에 소요되는 시간, 패킷을 받는 시간을 고려하여 20초 동안 sniff 를 함
    result = sniff(
        timeout = 20.0,
        filter = "ip",
        lfilter = signature_checker,
    )

    received_list = []
    for pkt in result:
        assert 3 < len(pkt.layers())    # Eth/IP/TCP/Raw
        payload = bytes(pkt[3])
        received_list.append(payload)
    
    return received_list

# scapy 에서 필요한 loopback 인터페이스 이름의 구해줌.
# 리눅스 / 윈도우 호환 가능
# netifaces 를 이용한 경우와 결과가 다르기 때문에, scapy 에서 지원하는 ifaces 를 사용해야 함.
def get_loopback_iface_name():
    for x, y in ifaces.items():
        if y.ip == loopback:
            return x


# send_msg_with_ip 는 타겟IP:타겟PORT 로 msg_list 에 있는 메시지들을 패킷으로 구성하여 send함
def send_msg_with_ip(target_ip, target_port, msg_list):
    for msg in msg_list:
        pkt = IP() / TCP() / Raw(msg)
        pkt[IP].dst = target_ip # src 는 자동으로 생성됨
        pkt[TCP].dport = target_port
        pkt[TCP].sport = 65535  # 임의의 포트
        send(pkt)


if __name__ == "__main__":
    local_sniffer(445)
