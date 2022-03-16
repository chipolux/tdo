from math import ceil


def pbin(n):
    """pretty print a binary representation 8 bits minimum"""
    s = bin(n)
    return '0b{}'.format(s[2:].rjust(8, '0'))


def encode():
    """
    example of encoding ascii to ascii85
    """
    si = 'POOP'
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
    e = ''.join(e)


def decode(s, conv=chr):
    """
    decode an ascii85 payload that has had whitespace stripped
    """
    output = []
    segments = ceil(len(s) / 5.0)
    for i in range(segments):
        offset = i * 5
        segment = s[offset:offset+5]
        pad = 5 - len(segment)
        segment += 'u' * pad
        so = []
        v3 = 0
        v3 += (ord(segment[0]) - 33) * (85**4)
        v3 += (ord(segment[1]) - 33) * (85**3)
        v3 += (ord(segment[2]) - 33) * (85**2)
        v3 += (ord(segment[3]) - 33) * (85**1)
        v3 += (ord(segment[4]) - 33) * (85**0)
        so.append(conv(v3 >> 3 * 8 & 0xff))
        so.append(conv(v3 >> 2 * 8 & 0xff))
        so.append(conv(v3 >> 1 * 8 & 0xff))
        so.append(conv(v3 >> 0 * 8 & 0xff))
        so = ''.join(so[:5-pad])
        output.append(so)
    return ''.join(output)


def extract(path):
    """
    extract a single adobe ascii85 payload from a file
    """
    with open(path, 'r') as f:
        data = f.read()
    start = -1
    end = -1
    for i in range(len(data)):
        if data[i:i+2] == '<~':
            start = i + 2
        elif data[i:i+2] == '~>':
            end = i
    return data[start:end].replace('\n', '').replace(' ', '')


def layer0():
    """
    perform decoding of layer 0 into layer 1
    """
    with open('l1.txt', 'w') as f:
        f.write(decode(extract('l0.txt')))


def layer1():
    """
    perform decoding of layer 1 into layer 2
    """

    def conv(c):
        c = c ^ 0x55
        return chr((c >> 1) | ((c & 0b1) << 7))

    with open('l2.txt', 'w') as f:
        f.write(decode(extract('l1.txt'), conv))


if __name__ == '__main__':
    layer0()
    layer1()
