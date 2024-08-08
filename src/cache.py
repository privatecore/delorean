from collections import OrderedDict

class LRUCache:
    def __init__(self, capacity=4096):
        self.cache = OrderedDict()
        self.capacity = capacity

    def get(self, key):
        if key not in self.cache:
            return None
        value = self.cache.pop(key)
        self.cache[key] = value
        return value

    def put(self, key, value):
        if key in self.cache:
            self.cache.pop(key)
        elif len(self.cache) >= self.capacity:
            self.cache.popitem(last=False)
        self.cache[key] = value

class CacheEntry:
    def __init__(self, address, timestamp):
        self.address = address
        self.timestamp = timestamp
