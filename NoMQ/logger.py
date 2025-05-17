import time 

# SimpleLogger implementation (if not provided)
class SimpleLogger:
    def __init__(self, level='INFO'):
        self.level = level
        self.levels = {'DEBUG': 0, 'INFO': 1, 'WARNING': 2, 'ERROR': 3}
    
    def _log(self, level, msg):
        if self.levels.get(level, 0) >= self.levels.get(self.level, 0):
            print(f"[{level}] {msg}")
    
    def info(self, msg): self._log('INFO', msg)
    def warning(self, msg): self._log('WARNING', msg)
    def error(self, msg): self._log('ERROR', msg)
    def debug(self, msg): self._log('DEBUG', msg)
