from src.server import Server

if __name__ == '__main__':
    server = Server('proxy.conf')
    server.start()
