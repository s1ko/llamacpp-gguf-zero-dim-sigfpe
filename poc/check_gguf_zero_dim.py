#!/usr/bin/env python3
import struct
import sys

SCALAR_SIZES = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
TYPE_STRING = 8
TYPE_ARRAY = 9
MAX_DIMS = 4


class Truncated(Exception):
    pass


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, size):
        if size < 0 or self.pos + size > len(self.data):
            raise Truncated()
        chunk = self.data[self.pos:self.pos + size]
        self.pos += size
        return chunk

    def unpack(self, fmt):
        size = struct.calcsize(fmt)
        return struct.unpack(fmt, self.take(size))[0]

    def string(self):
        return self.take(self.unpack('<Q'))

    def skip_value(self, gguf_type):
        if gguf_type in SCALAR_SIZES:
            self.take(SCALAR_SIZES[gguf_type])
        elif gguf_type == TYPE_STRING:
            self.string()
        elif gguf_type == TYPE_ARRAY:
            elem_type = self.unpack('<I')
            for _ in range(self.unpack('<Q')):
                self.skip_value(elem_type)
        else:
            raise ValueError('unknown metadata type %d' % gguf_type)


def zero_dim_tensors(data):
    reader = Reader(data)
    if reader.take(4) != b'GGUF':
        raise ValueError('not a GGUF file')
    version = reader.unpack('<I')
    if version < 2:
        raise ValueError('unsupported GGUF version %d' % version)
    n_tensors = reader.unpack('<q')
    n_kv = reader.unpack('<q')
    for _ in range(n_kv):
        reader.string()
        reader.skip_value(reader.unpack('<I'))
    findings = []
    try:
        for _ in range(n_tensors):
            name = reader.string().decode('utf-8', 'replace')
            n_dims = reader.unpack('<I')
            if n_dims > MAX_DIMS:
                raise ValueError('tensor %r has n_dims=%d' % (name, n_dims))
            ne = [reader.unpack('<q') for _ in range(n_dims)]
            if any(dim == 0 for dim in ne[1:]):
                findings.append((name, ne))
            reader.take(12)
    except Truncated:
        pass
    return findings


def main(paths):
    status = 0
    for path in paths:
        with open(path, 'rb') as handle:
            data = handle.read()
        try:
            findings = zero_dim_tensors(data)
        except Truncated:
            print('%s: truncated while parsing' % path)
            status = max(status, 2)
            continue
        except ValueError as exc:
            print('%s: %s' % (path, exc))
            status = max(status, 2)
            continue
        for name, ne in findings:
            print('%s: tensor %r ne=%s has a zero dimension past ne[0]' % (path, name, ne))
            status = max(status, 1)
        if not findings:
            print('%s: ok' % path)
    return status


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit('usage: check_gguf_zero_dim.py file.gguf [...]')
    sys.exit(main(sys.argv[1:]))
