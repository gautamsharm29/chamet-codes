import sys
from capstone import *
from capstone.arm64 import *

def analyze_so(filepath, target_vma, text_offset, text_size):
    print(f"Analyzing {filepath}...")
    print(f"Target VMA: {hex(target_vma)}")
    print(f"Text Section: Offset={hex(text_offset)}, Size={hex(text_size)}")

    try:
        with open(filepath, 'rb') as f:
            # For .so files, the text section offset in file corresponds to its VMA
            # But we must read from the file offset.
            # The VMA used for disassembly should match the VMA in memory.
            # In our case, VMA == Offset for .text usually.

            f.seek(text_offset)
            code = f.read(text_size)
    except FileNotFoundError:
        print(f"Error: File {filepath} not found.")
        return

    # Initialize Capstone for ARM64
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True # Enable details

    base_address = text_offset # Assuming VMA == Offset

    # Store potential base addresses from ADRP
    # Key: Register Name (e.g., 'x0'), Value: (Page Address, Instruction Address)
    adrp_regs = {}

    # We want to print context around the match.
    # We'll store instructions in a buffer.
    # When a match is found, we print the buffer and continue printing a few more.

    history = []
    MAX_HISTORY = 20

    count = 0
    match_found = False
    print_remaining = 0

    # Determine the page of the target VMA to filter ADRP quickly
    target_page = target_vma & ~0xFFF

    print("Disassembling...")

    for insn in md.disasm(code, base_address):
        count += 1
        if count % 100000 == 0:
            print(f"Processed {count} instructions...", end='\r')

        history.append(insn)
        if len(history) > MAX_HISTORY:
            history.pop(0)

        # If we are printing subsequent instructions after a match
        if print_remaining > 0:
            print(f"{hex(insn.address)}:\t{insn.mnemonic}\t{insn.op_str}")
            print_remaining -= 1
            if print_remaining == 0:
                print("-" * 40)
            continue

        # Analysis Logic

        # Check for ADRP
        if insn.id == ARM64_INS_ADRP:
            if len(insn.operands) > 1:
                reg = insn.reg_name(insn.operands[0].reg)
                imm = insn.operands[1].imm
                # Capstone returns the calculated page address in imm
                page_address = imm

                # Optimization: Only store if it matches the target page
                if page_address == target_page:
                     # print(f"Potential page match at {hex(insn.address)} for reg {reg}")
                     adrp_regs[reg] = (page_address, insn.address)

        # Check for ADD or LDR that uses the register
        elif insn.id in [ARM64_INS_ADD, ARM64_INS_LDR]:
             # We need to find the register being used as source/base
            target_reg = None
            offset = 0

            # Check ADD
            if insn.id == ARM64_INS_ADD:
                # ADD x0, x1, #imm
                if len(insn.operands) > 2 and insn.operands[1].type == ARM64_OP_REG and insn.operands[2].type == ARM64_OP_IMM:
                     target_reg = insn.reg_name(insn.operands[1].reg)
                     offset = insn.operands[2].imm

            # Check LDR
            elif insn.id == ARM64_INS_LDR:
                # LDR x0, [x1, #imm]
                if len(insn.operands) > 1 and insn.operands[1].type == ARM64_OP_MEM:
                     target_reg = insn.reg_name(insn.operands[1].mem.base)
                     offset = insn.operands[1].mem.disp

            if target_reg and target_reg in adrp_regs:
                page_addr, adrp_addr = adrp_regs[target_reg]

                # Verify distance (e.g. within 200 instructions - 800 bytes)
                if insn.address - adrp_addr < 800:
                    final_addr = page_addr + offset
                    if final_addr == target_vma:
                        print(f"\nMatch found at {hex(insn.address)}!")
                        print(f"Referencing string at {hex(target_vma)}")
                        print("-" * 40)
                        # Print history (excluding current, which will be printed next)
                        for h_insn in history[:-1]:
                             print(f"{hex(h_insn.address)}:\t{h_insn.mnemonic}\t{h_insn.op_str}")

                        # Print current
                        print(f"{hex(insn.address)}:\t{insn.mnemonic}\t{insn.op_str} <--- MATCH")

                        print_remaining = 20 # Print next 20 instructions
                        match_found = True

    print("\nAnalysis complete.")

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python3 analyze_so.py <filepath> <target_vma> <text_offset> <text_size>")
        sys.exit(1)

    filepath = sys.argv[1]
    # Check if hex string or int
    target_vma = int(sys.argv[2], 16) if sys.argv[2].startswith('0x') else int(sys.argv[2])
    text_offset = int(sys.argv[3], 16) if sys.argv[3].startswith('0x') else int(sys.argv[3])
    text_size = int(sys.argv[4], 16) if sys.argv[4].startswith('0x') else int(sys.argv[4])

    analyze_so(filepath, target_vma, text_offset, text_size)
