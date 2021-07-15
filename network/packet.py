from scapy.all import *
from ordered_set import OrderedSet as oSet

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

# scapy 에서 필요한 loopback 인터페이스 이름의 구해줌.
# 리눅스 / 윈도우 호환 가능
# netifaces 를 이용한 경우와 결과가 다르기 때문에, scapy 에서 지원하는 ifaces 를 사용해야 함.
def get_loopback_iface_name():
    for x, y in ifaces.items():
        if y.ip == loopback:
            return x

def send_msg_with_ip(target_ip, target_port, msg_list):
    for msg in msg_list:
        pkt = Ether() / IP() / TCP() / Raw(msg)
        pkt[IP].dst = target_ip # src 는 자동으로 생성됨
        pkt[TCP].dport = target_port
        pkt[TCP].sport = 60000  # 임의의 포트
        sendp(pkt)
        pkt.show()
        print("sended", bytes(pkt))



if __name__ == "__main__":
    print(sniffer(445))
