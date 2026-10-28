#!/usr/bin/env python3
import struct
import sys


def build(ne):
    out = b'GGUF'
    out += struct.pack('<I', 3)
    out += struct.pack('<q', 1)
    out += struct.pack('<q', 0)
    out += struct.pack('<Q', 1) + b'x'
    out += struct.pack('<I', len(ne))
    for dim in ne:
        out += struct.pack('<q', dim)
    out += struct.pack('<I', 0)
    out += struct.pack('<Q', 0)
    out += b'\x00' * ((-len(out)) % 32)
    return out


if __name__ == '__main__':
    dims = [int(a) for a in sys.argv[1:]] or [1, 0]
    sys.stdout.buffer.write(build(dims))
