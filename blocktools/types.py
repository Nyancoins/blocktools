import struct, binascii


def uint1(stream):
    return ord(stream.read(1))

def uint2(stream):
    return struct.unpack('H', stream.read(2))[0]

def uint4(stream):
    return struct.unpack('I', stream.read(4))[0]

def uint8(stream):
    return struct.unpack('Q', stream.read(8))[0]

def hash32(stream):
    return stream.read(32)[::-1]

def pack_uint1(val):
    return struct.pack('B', val)

def pack_uint2(val):
    return struct.pack('H', val)

def pack_uint4(val):
    return struct.pack('I', val)

def pack_uint8(val):
    return struct.pack('Q', val)

def pack_hash32(val):
    return val[::-1]

def time(stream):
    time = uint4(stream)
    return time

def varint(stream):
    size = uint1(stream)

    if size < 0xfd:
        return size
    if size == 0xfd:
        return uint2(stream)
    if size == 0xfe:
        return uint4(stream)
    if size == 0xff:
        return uint8(stream)
    return -1

def pack_varint(val):

    if val < 0xfd:
        return struct.pack('B', val)

    if val < 0xffff:
        return '\x02' + pack_uint2(val)

    if val < 0xffffffff:
        return '\x04' + pack_uint4(val)

    if val < 0xffffffffffffffff:
        return '\x08' + pack_uint8(val)

    raise AssertionError("VarInt is too large to store!")

def hashStr(bytebuffer):
    return binascii.hexlify(bytebuffer)

