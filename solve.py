import json
import os
import struct
import subprocess
from itertools import cycle
from math import ceil

from Crypto.Cipher import AES

import ipv4

# parity bit lookup table for all 7 bit integers
PARITY_TABLE = {i: 0 if bin(i).count("1") % 2 == 0 else 1 for i in range(0x80)}


def parity(b):
    """
    check if byte passes parity check using precalculated 7bit parity table
    """
    return PARITY_TABLE[b >> 1] == (b & 0b1)


def find_key(encrypted, expected):
    """find XOR encryption key"""
    for i in range(0xFF + 1):
        if encrypted ^ i == expected:
            return i


def aes_unwrap_key(wkey, kek, iv):
    iv = struct.unpack(">Q", iv)[0]
    buf = list(struct.unpack(f">{len(wkey) // 8}Q", wkey))
    blocks = len(buf) - 1

    for j in range(5, -1, -1):
        for i in range(blocks, 0, -1):
            buf[0] = buf[0] ^ (blocks * j + i)
            data = struct.pack(">2Q", buf[0], buf[i])
            cipher = AES.new(kek, AES.MODE_ECB)
            buf[0], buf[i] = struct.unpack(">2Q", cipher.decrypt(data))

    if buf[0] == iv:
        return struct.pack(f">{len(buf) - 1}Q", *buf[1:])


def pbin(n):
    """pretty print a binary representation 8 bits minimum"""
    s = bin(n)
    return "0b{}".format(s[2:].rjust(8, "0"))


def encode():
    """
    example of encoding ascii to ascii85
    """
    si = "POOP"
    e = []
    v1 = 0
    v1 += ord(si[0]) << (3 * 8)
    v1 += ord(si[1]) << (2 * 8)
    v1 += ord(si[2]) << (1 * 8)
    v1 += ord(si[3]) << (0 * 8)
    v2 = v1
    v2, c4 = divmod(v2, 85)
    v2, c3 = divmod(v2, 85)
    v2, c2 = divmod(v2, 85)
    v2, c1 = divmod(v2, 85)
    v2, c0 = divmod(v2, 85)
    e.append(chr(c0 + 33))
    e.append(chr(c1 + 33))
    e.append(chr(c2 + 33))
    e.append(chr(c3 + 33))
    e.append(chr(c4 + 33))
    e = "".join(e)


def extract(path):
    """
    extract a single adobe ascii85 payload from a file
    """
    with open(path, "r") as f:
        data = f.read()
    start = -1
    end = -1
    for i in range(len(data)):
        if data[i : i + 2] == "<~":
            start = i + 2
        elif data[i : i + 2] == "~>":
            end = i
    return data[start:end].replace("\n", "").replace(" ", "")


def decode(s, conv=lambda x: x):
    """
    decode an ascii85 payload that has had whitespace stripped
    """
    output = []
    segments = ceil(len(s) / 5.0)
    for i in range(segments):
        offset = i * 5
        segment = s[offset : offset + 5]
        pad = 5 - len(segment)
        segment += "u" * pad
        parts = []
        value = 0
        value += (ord(segment[0]) - 33) * (85 ** 4)
        value += (ord(segment[1]) - 33) * (85 ** 3)
        value += (ord(segment[2]) - 33) * (85 ** 2)
        value += (ord(segment[3]) - 33) * (85 ** 1)
        value += (ord(segment[4]) - 33) * (85 ** 0)
        parts.append(conv(value >> 3 * 8 & 0xFF))
        parts.append(conv(value >> 2 * 8 & 0xFF))
        parts.append(conv(value >> 1 * 8 & 0xFF))
        parts.append(conv(value >> 0 * 8 & 0xFF))
        output.extend(parts[: 4 - pad])
    return output


def layer0():
    """perform decoding of layer 1"""
    with open("l1.txt", "w") as f:
        f.write("".join(decode(extract("l0.txt"), chr)))


def layer1():
    """perform decoding of layer 2"""

    def conv(c):
        c = c ^ 0x55
        return chr((c >> 1) | ((c & 0b1) << 7))

    with open("l2.txt", "w") as f:
        f.write("".join(decode(extract("l1.txt"), conv)))


def layer2():
    """perform decoding of layer 3"""
    data = list(filter(parity, decode(extract("l2.txt"))))
    output = []
    byte = 0
    for i, b in enumerate(data):
        i = (i % 8) + 1
        if i > 1:
            byte |= (b >> 8 - (i - 1)) & 0xFF
            output.append(chr(byte))
        byte = ((b >> 1) << i) & 0xFF

    with open("l3.txt", "w") as f:
        f.write("".join(output))


def layer3():
    """perform decoding of layer 4"""
    with open("key.json", "r") as f:
        key = json.load(f)

    data = decode(extract("l3.txt"))
    output = []
    for e, k in zip(data, cycle(key)):
        output.append(chr(e ^ k))

    with open("l4.txt", "w") as f:
        f.write("".join(output))


def layer4():
    """perform decoding of layer 5"""
    data = bytes(decode(extract("l4.txt")))
    output = []
    offset = 0
    max_offset = len(data)
    while offset < max_offset:
        p = ipv4.IPv4Packet(data[offset:])
        offset += p.total_length
        if p.valid:
            output.append(p.data.content.decode("ascii"))

    with open("l5.txt", "w") as f:
        f.write("".join(output))


def layer5():
    """perform decoding of layer 6"""
    data = decode(extract("l5.txt"))

    key = aes_unwrap_key(bytes(data[40:80]), bytes(data[:32]), bytes(data[32:40]))
    key = "".join(map("{:02x}".format, key))
    iv = "".join(map("{:02x}".format, data[80:96]))

    subprocess.run(
        [
            "openssl",
            "aes-256-ctr",
            "-d",
            "-K",
            key,
            "-iv",
            iv,
            "-out",
            "l6.txt",
        ],
        input=bytes(data[96:]),
        check=True,
    )


if __name__ == "__main__":
    if not os.path.exists("l1.txt"):
        layer0()
    if not os.path.exists("l2.txt"):
        layer1()
    if not os.path.exists("l3.txt"):
        layer2()
    if not os.path.exists("l4.txt"):
        layer3()
    if not os.path.exists("l5.txt"):
        layer4()
    if not os.path.exists("l6.txt"):
        layer5()
