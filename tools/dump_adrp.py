import sys
from capstone import *
from capstone.arm64 import *

def dump_adrp(filepath, text_offset, text_size):
    print(f"Dumping ADRP from {filepath}...")
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

    for insn in md.disasm(code, base_address):
        if insn.id == ARM64_INS_ADRP:
            if len(insn.operands) > 1:
                imm = insn.operands[1].imm
                print(f"{hex(insn.address)}: {insn.mnemonic} {insn.op_str} -> page={hex(imm)}")

if __name__ == "__main__":
    filepath = sys.argv[1]
    text_offset = int(sys.argv[2], 16)
    text_size = int(sys.argv[3], 16)
    dump_adrp(filepath, text_offset, text_size)
