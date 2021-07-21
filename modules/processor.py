from abc import ABCMeta, abstractmethod

"""
<API 명세서>
1. 공격 명령 내리기 : http://url/command/<int:id>
2. 포트 스캔 결과 받기 : http://url/scan-result
3. Agnet로부터 'ip , ETC 정보 전달' 보내기 : http://url/agent/info
4. 다운로드 : http:url/download/
"""

class Processor(metaclass = ABCMeta):
    base_url = "http://localhost:9000"
    report_url = "/report/<id>"
    scan_url = "/scan-result"
    introduce_url = "/agent/info"

    def __init__(self, cmd):
        self.cmd = cmd
        assert "type" in cmd
        self.type = cmd["type"]
        pass

    @abstractmethod
    def run_cmd(self):
        pass

    @abstractmethod
    def report(self):
        pass

    def __str__(self):
        return f"Command: {self.cmd}"
    
    def check_cmd(self, fields):
        for field in fields:
            assert field in self.cmd
