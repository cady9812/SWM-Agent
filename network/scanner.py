import json
import xmltodict
from libnmap.process import NmapProcess

import json
import logging
import logging.config
import pathlib
log_config = (pathlib.Path(__file__).parent.resolve().parents[0].joinpath("log_config.json"))
config = json.load(open(str(log_config)))
logging.config.dictConfig(config)
logger = logging.getLogger(__name__)

# 옵션을 받아서 target 에 nmap 을 수행하고, 그 결과를 xml 형태로 반환함
# usage: nmap_target("localhost", "-A", "-p 8000,22,90,445")
def nmap_target(target, *options):
    SUCCESS = 0
    result = ''
    nm = NmapProcess(target, options = ' '.join(options))
    v = nm.run()
    if v == SUCCESS:
        result = nm.stdout
    else:
        exit(1)

    return result


def nmap_parser(xml_content):
    # json 형태로 바꿔 변수에 저장
    str_content = json.dumps(xmltodict.parse(xml_content), indent=4, sort_keys=True)
    json_content = json.loads(str_content)

    json_data = json_content["nmaprun"]["host"]["ports"]
    json_data = json_data["port"]
    res = []

    # 나온 포트가 1개인 경우, list 형태로 만들어줌.
    # 나온 포트가 2개 이상인 경우와 일관성을 맞춰주기 위함
    if isinstance(json_data, dict):
        json_data = [ json_data ]

    for data in json_data:
        d = {}
        if "@portid" in data:
            d["port"] = data["@portid"]
        if "@protocol" in data:
            d["protocol"] = data["@protocol"]
        if "service" in data:
            if "@name" in data["service"]:
                d["service_name"] = data["service"]["@name"]
            if "@product" in data["service"]:
                d["service_product"] = data["service"]["@product"]
            if "@version" in data["service"]:
                d["service_version"] = data["service"]["@version"]

            # open, filtered, closed, open | filtered
            if "@state" in data["state"]:
                d["state"] = data["state"]["@state"]

        # 구체적인 프로그램 정보
        if "script" in data:
            ids = data["script"]

            if isinstance(ids, dict):   # @id 가 하나만 나왔을 경우에 대비
                ids = [ ids ]

            for item in ids:
                if item.get('@id') == "http-generator":
                    if '@output' in item:
                        # e.g. "WordPress 5.7.2"
                        # ' ' 을 기준으로 프로그램과 버전을 나눌까..?
                        d["program_name"] = item["@output"]

        res.append(d)
    
    return res

# For debug
if __name__ == "__main__":
    a = nmap_target("172.30.1.26", "-A", "-Pn", "-p 445")
    res = nmap_parser(a)
