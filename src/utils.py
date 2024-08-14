import struct

def create_fake_client_hello_packet(server_name):
    packet = bytearray()

    packet.extend(b'\x16\x03\x01\x00\x00')  # Record Layer
    packet.extend(b'\x01\x00\x00\x00')      # Handshake
    packet.extend(b'\x03\x03')              # Version
    packet.extend(b'\xb6\xb2\x6a\xfb\x55\x5e\x03\xd5\x65\xa3\x6a\xf0\x5e\xa5\x43\x02\x93\xb9\x59\xa7\x54\xc3\xdd\x78\x57\x58\x34\xc5\x82\xfd\x53\xd1')
    packet.append(0x00)
    packet.extend(b'\x00\x04\x00\x01\x00\xff')  # Session ID
    packet.append(0x01)                         # Cipher Suites
    packet.append(0x00)                         # Compression Methods

    extensions = bytearray()
    extensions.extend(b'\x00\x00')
    sni = bytearray()
    sni.extend(b'\x00\x0c\x00\x00')
    sni_name = server_name.encode()
    sni.extend(struct.pack('!H', len(sni_name)))
    sni.extend(sni_name)
    extensions.extend(b'\x00\x0e')
    extensions.extend(sni)

    extensions.extend(b'\x00\x0d\x00\x20\x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03')
    extensions.extend(b'\x00\x0f\x00\x01\x01')

    ext_len = len(extensions)
    extensions = struct.pack('!H', ext_len) + extensions
    packet.extend(extensions)

    handshake_len = len(packet) - 5
    packet[3] = (handshake_len >> 8) & 0xff
    packet[4] = handshake_len & 0xff

    return bytes(packet)
