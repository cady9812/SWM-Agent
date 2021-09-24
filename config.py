import os
# Network Configuration
if "SERVER_IP" in os.environ:
    SERVER_IP = os.environ["SERVER_IP"]
else:
    print("No Server Ip Found")
    SERVER_IP = "172.17.0.2"
WEB_PORT = 5000
TCP_PORT = 9000
AGENT_LOG_PORT = 5002

# Colors
END = "\033[0m"
YELLOW = "\033[33m"
MAGENT = "\033[35m"
GREEN = "\033[32m"
BLUE = "\033[34m"
CYAN = "\033[36m"
RED = "\033[31m"
