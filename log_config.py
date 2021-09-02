import logging
import logging.config
import json
# logstash import 안해도 되는 것 같음


with open("config.ini") as f:
    config = json.loads(f.read())
    SERVER_IP = config["SERVER_IP"]
    SERVER_PORT = config["LOG_PORT"]


def get_custom_logger(name):
    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "basic": {
                "format": "%(asctime)s [%(levelname)s] %(filename)s:%(lineno)d %(name)s:%(funcName)s\n> %(message)s",
                "datefmt": "%Y-%m-%d | %H:%M:%S",   # 한글 쓰면 windows 인코딩이 달라서 문제가 발생하는 듯 함.
            }
        },

        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": "DEBUG",
                "formatter": "basic"
            },
            # reference: https://github.com/vklochan/python-logstash
            'logstash': {
                'level': 'INFO',
                'class': 'logstash.TCPLogstashHandler',
                'host': 'SERVER_IP',
                'port': SERVER_PORT, # Default value: 5959
                'version': 1, # Version of logstash event schema. Default value: 0 (for backward compatibility of the library)
                'message_type': 'logstash',  # 'type' field in logstash message. Default value: 'logstash'.
                'fqdn': False, # Fully qualified domain name. Default value: false.
                # 'tags': ['tag1', 'tag2'], # list of tags. Default: None.
            },
        },

        "loggers": {
            "": {
                "level": "DEBUG",
                # "handlers": ["console", "logstash"],  # TODO
                "handlers": ["console"],
                "propagate": False,
            }
        }
    }

    logging.config.dictConfig(config)
    return logging.getLogger(name)
 

if __name__ == "__main__":
    logger = get_custom_logger(__name__)
    logger.info("log test")
