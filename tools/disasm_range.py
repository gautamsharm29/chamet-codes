import sys
from capstone import *
from capstone.arm64 import *

def disasm_range(filepath, text_offset, text_size, start_addr, num_insns):
    print(f"Disassembling {num_insns} instructions starting at {hex(start_addr)}...")
    try:
        with open(filepath, 'rb') as f:
            f.seek(text_offset)
            code = f.read(text_size)
    except FileNotFoundError:
        print(f"Error: File {filepath} not found.")
        return

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    base_address = text_offset

    # Calculate offset into buffer
    offset = start_addr - base_address
    if offset < 0 or offset >= len(code):
        print("Address out of range.")
        return

    code_slice = code[offset:]
    count = 0
    for insn in md.disasm(code_slice, start_addr):
        print(f"{hex(insn.address)}:\t{insn.mnemonic}\t{insn.op_str}")
        count += 1
        if count >= num_insns:
            break

if __name__ == "__main__":
    filepath = sys.argv[1]
    text_offset = int(sys.argv[2], 16)
    text_size = int(sys.argv[3], 16)
    start_addr = int(sys.argv[4], 16)
    num_insns = int(sys.argv[5])
    disasm_range(filepath, text_offset, text_size, start_addr, num_insns)
