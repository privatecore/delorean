import socket
import threading
import signal
import sys
from src.config import Config
from src.logger import get_logger
from src.cache import LRUCache
from src.handler import ConnectionHandler

class Server:
    def __init__(self, config_file):
        self.config = Config(config_file)
        self.dns_cache = LRUCache()
        self.logger = get_logger(True)
        self.handler = ConnectionHandler(self.config, self.dns_cache, self.logger)
        self.servers = []
        self.shutdown = threading.Event()

    def start(self):
        self.config.load()
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        self.logger.debug("Starting all servers")
        for port in self.config.ports:
            thread = threading.Thread(target=self.start_server, args=(port,))
            thread.start()

    def start_server(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.config.ip, port))
            server_socket.listen(5)
            self.servers.append(server_socket)

            self.logger.debug(f"Server started on {self.config.ip}:{port}")

            while not self.shutdown.is_set():
                try:
                    client_socket, addr = server_socket.accept()
                    self.logger.debug(f"Accepted connection from {addr}")
                    thread = threading.Thread(target=self.handler.handle_connection, args=(client_socket,))
                    thread.start()
                except socket.timeout:
                    continue

    def stop(self):
        self.shutdown.set()
        for server in self.servers:
            server.close()
        self.logger.debug("All servers stopped")

    def signal_handler(self, signum, frame):
        self.logger.debug(f"Received signal {signum}, shutting down")
        self.stop()
        sys.exit(0)
