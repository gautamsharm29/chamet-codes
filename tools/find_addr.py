import sys
import struct

def find_address(filepath, target_addr):
    print(f"Searching for {hex(target_addr)} in {filepath}...")
    target_bytes = struct.pack('<Q', target_addr) # 64-bit little endian
    target_bytes_32 = struct.pack('<I', target_addr) # 32-bit (maybe?)

    with open(filepath, 'rb') as f:
        data = f.read()

    offsets = []
    start = 0
    while True:
        idx = data.find(target_bytes, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1

    print(f"Found 64-bit address at offsets: {[hex(o) for o in offsets]}")

    offsets_32 = []
    start = 0
    while True:
        idx = data.find(target_bytes_32, start)
        if idx == -1:
            break
        offsets_32.append(idx)
        start = idx + 1

    print(f"Found 32-bit address at offsets: {[hex(o) for o in offsets_32]}")

if __name__ == "__main__":
    filepath = sys.argv[1]
    target_addr = int(sys.argv[2], 16)
    find_address(filepath, target_addr)
