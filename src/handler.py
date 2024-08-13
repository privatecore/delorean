import socket
import struct
import time
from src.cache import LRUCache, CacheEntry

class ConnectionHandler:
    def __init__(self, config, dns_cache, logger):
        self.config = config
        self.dns_cache = dns_cache
        self.logger = logger

    def handle_connection(self, client_socket):
        try:
            client_socket.settimeout(30)
            reader = client_socket.makefile('rb')
            initial_bytes = reader.peek(5)[:5]

            if self.is_tls(initial_bytes):
                name, buffered_data = self.get_name_and_buffer_from_tls_connection(reader)
            else:
                name, buffered_data = self.get_name_and_buffer_from_http_connection(reader)

            if not name:
                self.logger.debug("Failed to get name from connection")
                return

            address = self.lookup_with_cache(name)
            if not address:
                self.logger.debug("Failed to lookup address")
                return

            backend_socket = socket.create_connection((address, client_socket.getsockname()[1]), timeout=30)
            backend_socket.settimeout(None)

            client_socket.sendall(buffered_data)

            self.pipe_sockets(client_socket, backend_socket)
        except Exception as e:
            self.logger.debug(f"Error handling connection: {e}")
        finally:
            client_socket.close()

    def is_tls(self, data):
        return len(data) > 3 and data[0] == 0x16 and data[1] == 0x03 and data[2] >= 0x01

    def get_name_and_buffer_from_http_connection(self, reader):
        self.logger.info("Extracting name from HTTP connection")
        buffered_data = bytearray()
        host = ""

        while True:
            line = reader.readline()
            if not line:
                break
            buffered_data.extend(line)
            if len(buffered_data) > self.max_buffered_data_size:
                raise ValueError("Buffered data exceeds maximum size")

            line = line.decode('utf-8').strip()

            if line.lower().startswith("host:"):
                host = line[5:].strip()
                self.logger.info(f"Extracted host from HTTP: {host}")

            if not line:
                break

        if not host:
            raise ValueError("Host header not found")

        # Read the remaining data in the buffer
        remaining_data = reader.read()
        if len(buffered_data) + len(remaining_data) > self.max_buffered_data_size:
            raise ValueError("Remaining data exceeds maximum buffer size")
        buffered_data.extend(remaining_data)

        return host, buffered_data

    def get_name_and_buffer_from_tls_connection(self, reader):
        self.logger.info("Extracting name from TLS connection")

        buffered_data = bytearray()

        # Read the initial 43 bytes of the ClientHello
        initial_bytes = reader.read(43)
        if len(initial_bytes) != 43:
            raise ValueError("Failed to read initial bytes")
        buffered_data.extend(initial_bytes)

        # Read the session ID length
        session_id_length = reader.read(1)
        if not session_id_length:
            raise ValueError("Failed to read session ID length")
        buffered_data.extend(session_id_length)

        session_id_length = ord(session_id_length)

        # Read the session ID
        session_id = reader.read(session_id_length)
        if len(buffered_data) + len(session_id) > self.max_buffered_data_size:
            raise ValueError("Buffered data exceeds maximum size")
        buffered_data.extend(session_id)

        # Read the cipher suites length
        cipher_suites_length_bytes = reader.read(2)
        if len(cipher_suites_length_bytes) != 2:
            raise ValueError("Failed to read cipher suites length")
        buffered_data.extend(cipher_suites_length_bytes)
        cipher_suites_length = struct.unpack('!H', cipher_suites_length_bytes)[0]

        # Read the cipher suites
        cipher_suites = reader.read(cipher_suites_length)
        if len(buffered_data) + len(cipher_suites) > self.max_buffered_data_size:
            raise ValueError("Buffered data exceeds maximum size")
        buffered_data.extend(cipher_suites)

        # Read the compression methods length
        compression_methods_length = reader.read(1)
        if not compression_methods_length:
            raise ValueError("Failed to read compression methods length")
        buffered_data.extend(compression_methods_length)

        compression_methods_length = ord(compression_methods_length)

        # Read the compression methods
        compression_methods = reader.read(compression_methods_length)
        if len(buffered_data) + len(compression_methods) > self.max_buffered_data_size:
            raise ValueError("Buffered data exceeds maximum size")
        buffered_data.extend(compression_methods)

        # Read the extensions length
        extensions_length_bytes = reader.read(2)
        if len(extensions_length_bytes) != 2:
            raise ValueError("Failed to read extensions length")
        buffered_data.extend(extensions_length_bytes)
        extensions_length = struct.unpack('!H', extensions_length_bytes)[0]
        extensions_end_index = int(extensions_length)

        # Process extensions
        while extensions_end_index > 0:
            extension_type_bytes = reader.read(2)
            if len(extension_type_bytes) != 2:
                raise ValueError("Failed to read extension type")
            buffered_data.extend(extension_type_bytes)
            extension_type = struct.unpack('!H', extension_type_bytes)[0]

            extension_length_bytes = reader.read(2)
            if len(extension_length_bytes) != 2:
                raise ValueError("Failed to read extension length")
            buffered_data.extend(extension_length_bytes)
            extension_length = struct.unpack('!H', extension_length_bytes)[0]
            extensions_end_index -= 4 + int(extension_length)

            if extension_type == 0x0000:  # SNI extension type
                server_name_list_length_bytes = reader.read(2)
                if len(server_name_list_length_bytes) != 2:
                    raise ValueError("Failed to read server name list length")
                buffered_data.extend(server_name_list_length_bytes)

                server_name_type = reader.read(1)
                if not server_name_type:
                    raise ValueError("Failed to read server name type")
                buffered_data.extend(server_name_type)
                if server_name_type != b'\x00':  # Only consider type 0 (host_name)
                    break

                server_name_length_bytes = reader.read(2)
                if len(server_name_length_bytes) != 2:
                    raise ValueError("Failed to read server name length")
                buffered_data.extend(server_name_length_bytes)
                server_name_length = struct.unpack('!H', server_name_length_bytes)[0]

                server_name_bytes = reader.read(server_name_length)
                if len(buffered_data) + len(server_name_bytes) > self.max_buffered_data_size:
                    raise ValueError("Buffered data exceeds maximum size")
                buffered_data.extend(server_name_bytes)

                server_name = server_name_bytes.decode('utf-8')
                self.logger.info(f"Extracted server name from TLS: {server_name}")

                # Read the remaining data in the buffer
                remaining_data = reader.read()
                if len(buffered_data) + len(remaining_data) > self.max_buffered_data_size:
                    raise ValueError("Remaining data exceeds maximum buffer size")
                buffered_data.extend(remaining_data)

                return server_name, buffered_data
            else:
                extension_data = reader.read(extension_length)
                if len(buffered_data) + len(extension_data) > self.max_buffered_data_size:
                    raise ValueError("Buffered data exceeds maximum size")
                buffered_data.extend(extension_data)

        raise ValueError("SNI extension not found")

    def lookup_with_cache(self, hostname):
        entry = self.dns_cache.get(hostname)
        if entry:
            cache_entry = entry
            if time.time() - cache_entry.timestamp < self.config.ttl:
                return cache_entry.address
            self.lookup_raw(hostname)
            return cache_entry.address
        return self.lookup_raw(hostname)

    def lookup_raw(self, hostname):
        try:
            addresses = socket.getaddrinfo(hostname, None, socket.AF_INET6)
            for _, _, _, _, addr in addresses:
                if addr[0].startswith(self.config.prefix):
                    self.dns_cache.put(hostname, CacheEntry(addr[0], time.time()))
                    return addr[0]
        except socket.gaierror as e:
            self.logger.debug(f"Error during raw lookup: {e}")
        return None

    def pipe_sockets(self, src_socket, dst_socket):
        try:
            while True:
                data = src_socket.recv(4096)
                if not data:
                    break
                dst_socket.sendall(data)
        except Exception as e:
            self.logger.debug(f"Error piping data: {e}")
        finally:
            src_socket.close()
            dst_socket.close()
