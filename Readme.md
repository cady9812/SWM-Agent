# BAScope: agent

## Introduction

사이버 공격 시뮬레이션 서비스인 `BAScope` 에서 공격 모듈의 역할을 하고 있는 agent 이다. 웹 서버로부터 명령을 받아 해당 명령을 수행하고, 그 결과를 웹 서버로 보고하는 것이 핵심적인 기능이다. 

## Usage
python3 가 설치되어 있어야 한다.
Raw packet 전송 등을 위하여 관리자 권한으로 실행해야 한다.
```bash
sudo pip3 install -r requirements.txt
```