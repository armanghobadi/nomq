import time 

class SimpleLogger:
    """
    Simple logger for MicroPython to replace standard logging module.
    """
    def __init__(self, level='INFO'):
        self.levels = {'DEBUG': 10, 'INFO': 20, 'WARNING': 30, 'ERROR': 40}
        self.level = self.levels.get(level, 20)

    def debug(self, msg):
        if self.level <= self.levels['DEBUG']:
            print(f"{time.time():.3f} - DEBUG - {msg}")

    def info(self, msg):
        if self.level <= self.levels['INFO']:
            print(f"{time.time():.3f} - INFO - {msg}")

    def warning(self, msg):
        if self.level <= self.levels['WARNING']:
            print(f"{time.time():.3f} - WARNING - {msg}")

    def error(self, msg):
        if self.level <= self.levels['ERROR']:
            print(f"{time.time():.3f} - ERROR - {msg}")
