import logging
import os
import yaml

class Logger:
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.configure_logger()

    def configure_logger(self):
        log_config_path = os.path.join(os.path.dirname(__file__), '../../config/logging.yaml')
        with open(log_config_path, 'r') as file:
            config = yaml.safe_load(file)
            logging.config.dictConfig(config)

    def get_logger(self):
        return self.logger

def get_logger(name: str) -> logging.Logger:
    logger_instance = Logger(name)
    return logger_instance.get_logger()