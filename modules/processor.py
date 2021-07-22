from abc import ABCMeta, abstractmethod
import requests

"""
<API 명세서>
1. 공격 명령 내리기 : http://url/command/<int:id>
2. 포트 스캔 결과 받기 : http://url/scan-result
3. Agnet로부터 'ip , ETC 정보 전달' 보내기 : http://url/agent/info
4. 다운로드 : http:url/download/
"""

class Processor(metaclass = ABCMeta):
    base_url = "http://localhost:9000"
    scan_url = "/scan-result"
    introduce_url = "/agent/info"
    report_url = "/report/<id>"

    # Processor 마다 id 하나 부여됨
    id = -1

    def __init__(self, cmd, id):
        self.cmd = cmd
        assert "type" in cmd

        self.type = cmd["type"]
        self.id = str(id) if type(id) == int else id
        self.report_url = self.report_url.replace("<id>", self.id)
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

    def call_server(self, url, data):
        try:
            requests.post(url, json = data)
            return 1
        except:
            return 0

    def cmd_after_replacement(self, usage, replacements):
        import sys
        if int(sys.version.split()[0].split('.')[1]) < 8:
            for a, b in replacements:
                usage = usage.replace(a, b)
        else:
            # Reference: https://stackoverflow.com/a/55889140
            # python 3.8 need
            [ usage := usage.replace(a, b) for a, b in replacements ]

        return usage
