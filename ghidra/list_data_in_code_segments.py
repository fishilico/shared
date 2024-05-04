# List data parts present in code segments.
# This is helpful to identify jump tables and functions to be decompiled.

X86_NOP_PATTERNS = {
    "90",  # NOP
    "66 90",  # NOP
    "0f 1f 00",  # NOP dword ptr [RAX]
    "0f 1f 40 00",  # NOP dword ptr [RAX]
    "0f 1f 44 00",  # NOP dword ptr [RAX + RAX*0x1]
    "0f 1f 44 00 00",  # NOP dword ptr [RAX + RAX*0x1]
    "66 0f 1f 44 00 00",  # NOP word ptr [RAX + RAX*0x1]
    "0f 1f 80 00 00 00 00",  # NOP dword ptr [RAX]
    "0f 1f 84 00 00 00 00 00",  # NOP dword ptr [RAX + RAX*0x1]
    "66 0f 1f 84 00 00 00 00 00",  # NOP word ptr [RAX + RAX*0x1]
    "66 2e 0f 1f 84 00 00 00 00 00",  # NOP word ptr CS:[RAX + RAX*0x1]
    "66 2e 0f 1f 84 00 00 00 00 00 90",
    "66 66 2e 0f 1f 84 00 00 00 00 00",  # NOP dword ptr CS:[RAX + RAX*0x1]
    "66 2e 0f 1f 84 00 00 00 00 00 66 90",
    "66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00",
    "66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00",
    "66 2e 0f 1f 84 00 00 00 00 00 0f 1f 44 00",
    "66 2e 0f 1f 84 00 00 00 00 00 0f 1f 44 00 00",
    "66 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00",
    "66 2e 0f 1f 84 00 00 00 00 00 66 0f 1f 44 00 00",
    "66 2e 0f 1f 84 00 00 00 00 00 0f 1f 80 00 00 00 00",
    "66 2e 0f 1f 84 00 00 00 00 00 0f 1f 84 00 00 00 00 00",
    "66 2e 0f 1f 84 00 00 00 00 00 66 0f 1f 84 00 00 00 00 00",
    "66 2e 0f 1f 84 00 00 00 00 00 66 2e 0f 1f 84 00 00 00 00 00 66 90",
    "66 66 2e 0f 1f 84 00 00 00 00 00 66 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00",
    "66 2e 0f 1f 84 00 00 00 00 00 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 84 00 00 00 00 00",
    "66 2e 0f 1f 84 00 00 00 00 00 66 2e 0f 1f 84 00 00 00 00 00 66 2e 0f 1f 84 00 00 00 00 00",
    "66 2e 0f 1f 84 00 00 00 00 00 66 2e 0f 1f 84 00 00 00 00 00 66 2e 0f 1f 84 00 00 00 00 00 90",
    "66 2e 0f 1f 84 00 00 00 00 00 66 2e 0f 1f 84 00 00 00 00 00 66 2e 0f 1f 84 00 00 00 00 00 66 2e 0f 1f 84 00 00 00 00 00 90",
    "66 66 2e 0f 1f 84 00 00 00 00 00 66 66 2e 0f 1f 84 00 00 00 00 00 66 66 2e 0f 1f 84 00 00 00 00 00 66 66 2e 0f 1f 84 00 00 00 00 00 90",
}
for i in range(32):
    X86_NOP_PATTERNS.add("cc" + " cc" * i)  # INT3

NOP_PATTERNS = {
    "RISCV": {"13 00 00 00"},  # NOP
    "x86": X86_NOP_PATTERNS,
}[str(currentProgram.language.languageDescription.processor)]

for block in currentProgram.memory.blocks:
    addr = block.start
    try:
        if block.permissions & 1:
            # In an executable block, find data between instructions
            while addr.compareTo(block.end) <= 0:
                instr = currentProgram.listing.getInstructionAt(addr)
                if instr is not None:
                    addr = addr.add(instr.length)
                    continue
                data_start = addr
                addr = addr.add(1)
                while addr.compareTo(block.end) <= 0 and currentProgram.listing.getInstructionAt(addr) is None:
                    addr = addr.add(1)
                size = addr.subtract(data_start)
                data_bytes = getBytes(data_start, min(100, size))
                data_hex =  " ".join("%02x" % (x&0xff) for x in data_bytes)
                if data_hex not in X86_NOP_PATTERNS:
                    print("Data in %s at %s .. %s [%d]: %s" % (block.name, data_start, addr, size, data_hex))
        else:
            # In a non-executable block, find instructions in data
            while addr.compareTo(block.end) <= 0:
                instr = currentProgram.listing.getInstructionAt(addr)
                if instr is None:
                    addr = addr.add(1)
                    continue
                code_start = addr
                addr = addr.add(instr.length)
                while addr.compareTo(block.end) <= 0:
                    instr = currentProgram.listing.getInstructionAt(addr)
                    if instr is None:
                        break
                    addr = addr.add(instr.length)
                size = addr.subtract(code_start)
                print("Code in %s at %s .. %s [%d]" % (block.name, code_start, addr, size))
    except ghidra.program.model.address.AddressOverflowException as exc:
        print("Warning: ignoring exception %s" % exc)
