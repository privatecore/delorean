import logging

def get_logger(enable_logging):
    if enable_logging:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler(NullWriter())])
    return logging.getLogger()

class NullWriter:
    def write(self, p):
        return len(p)
