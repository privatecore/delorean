import json

class Config:
    def __init__(self, config_file='proxy.conf'):
        self.config_file = config_file
        self.ports = []
        self.ip = ""
        self.ttl = 0
        self.prefix = ""

    def load(self):
        with open(self.config_file, 'r') as file:
            data = json.load(file)
            self.ports = data['ports']
            self.ip = data['ip']
            self.ttl = data['ttl']
            self.prefix = data['prefix']

        if not self.ports or not self.ip or not self.ttl or not self.prefix:
            raise ValueError("Invalid configuration")
