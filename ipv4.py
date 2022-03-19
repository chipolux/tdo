import struct

EXPECTED_SOURCE = struct.unpack(">L", bytes([10, 1, 1, 10]))[0]
EXPECTED_DEST = struct.unpack(">L", bytes([10, 1, 1, 200]))[0]
EXPECTED_PORT = 42069


class IPv4Packet:
    """
    Parses an IPv4 packet from a bytestring.
    """

    def __init__(self, data):
        self.valid = False

        self.version = data[0] >> 4
        self.ihl = data[0] & 0xF  # size of header (in 32 bit words)
        self.ihl_b = self.ihl * 4  # size of header (in bytes)
        self.dscp = data[1] >> 2
        self.ecn = data[1] & 0x3
        self.total_length = struct.unpack(">H", data[2:4])[0]
        self.identification = struct.unpack(">H", data[4:6])[0]
        self.flags = data[6] >> 5
        self.fragment_offset = struct.unpack(">H", bytes([data[6] & 0x1F, data[7]]))[0]
        self.ttl = data[8]
        self.protocol = data[9]
        self.checksum = struct.unpack(">H", data[10:12])[0]
        self.source = struct.unpack(">L", data[12:16])[0]
        self.source_ip = f"{data[12]}.{data[13]}.{data[14]}.{data[15]}"
        self.dest = struct.unpack(">L", data[16:20])[0]
        self.dest_ip = f"{data[16]}.{data[17]}.{data[18]}.{data[19]}"
        self.options = data[20 : 20 + (self.ihl_b - 20)]
        self.data = UDPPacket(
            self.source, self.dest, data[self.ihl_b : self.total_length]
        )

        checksum = sum(struct.unpack(f">{self.ihl_b // 2}H", data[: self.ihl_b]))
        checksum = (checksum + (checksum >> 16)) & 0xFFFF
        self.valid = (
            checksum == 0xFFFF
            and self.source == EXPECTED_SOURCE
            and self.dest == EXPECTED_DEST
            and self.data.valid
        )

    def __str__(self):
        return (
            "<IPv4Packet("
            f"valid={self.valid}, "
            f"source={self.source_ip}, "
            f"dest={self.dest_ip}, "
            f"size={self.total_length}"
            ")>"
        )

    def __repr__(self):
        return str(self)


class UDPPacket:
    """
    Parses a UDP packet from a bytestring.
    """

    def __init__(self, source, dest, data):
        self.valid = False

        self.source, self.dest, self.length, self.checksum = struct.unpack(
            ">HHHH", data[0:8]
        )
        self.content = data[8:]

        buf = struct.pack(">LLxBH", source, dest, 0x11, self.length) + data
        buf += b"\x00" * (len(buf) % 2)
        checksum = sum(struct.unpack(f">{len(buf) // 2}H", buf))
        checksum = (checksum + (checksum >> 16)) & 0xFFFF
        self.valid = checksum == 0xFFFF and self.dest == EXPECTED_PORT

    def __str__(self):
        return (
            "<UDPPacket("
            f"valid={self.valid}, "
            f"source={self.source}, "
            f"dest={self.dest}, "
            f"length={self.length}"
            ")>"
        )

    def __repr__(self):
        return str(self)
