# Fix the PLT functions of RISC-V binaries
#
# For example, some libraries used in Hack-a-Sat 3 finals event used the
# following PLT trampoline:
#
#                             FUN_000130d0
#        000130d0 17 4e 00 00          auipc      t3,0x4
#        000130d4 03 2e 4e f4          lw         t3,-0xbc(t3=>->CFE_ES_RunLoop)
#        000130d8 67 03 0e 00          jalr       t1,t3=>CFE_ES_RunLoop,0x0
#        000130dc 13 00 00 00          nop
#
# This jumped to a function from the GOT with "jalr t1,...", to put the next
# address in t1. Ghidra interpreted this as a call instead of a jump.
#
# This script finds every function like this example, adds a "Flow Override"
# to "jalr" to make is "call-return" and makes such a short function "Thunked",
# to make cross-references and names simpler.

def fix_plt_function(fct):
    # Detect that the function is a PLT one, and fix it
    fct_addr = fct.symbol.address
    cu = currentProgram.listing.getCodeUnitAt(fct_addr)
    if not str(cu).startswith("auipc t3,"):
        return
    cu = currentProgram.listing.getCodeUnitAt(fct_addr.add(4))
    if not str(cu).startswith("lw t3,"):
        return
    # NOP may not be not-disassembled, if Ghidra detected a call to a function which does not return (like __assert_fail)
    # This is why the following 'if' is commented. It has been replaced with binary matching.
    #cu = currentProgram.listing.getCodeUnitAt(fct_addr.add(12))
    #if str(cu) != "nop":
    #    return
    nop_bytes = getBytes(fct_addr.add(12), 4)
    if list(getBytes(fct_addr.add(12), 4)) != [0x13, 0, 0, 0]:
        return
    instr = currentProgram.listing.getInstructionAt(fct_addr.add(8))
    if str(instr) != "jalr t1,t3,0x0":
        return
    if instr.getFlowOverride() == ghidra.program.model.listing.FlowOverride.NONE:
        print("Setting flow override of {} ({})".format(fct_addr.add(8), instr))
        instr.setFlowOverride(ghidra.program.model.listing.FlowOverride.CALL_RETURN)
    refs = currentProgram.referenceManager.getReferencesFrom(fct_addr.add(8))
    if len(refs) != 1:
        raise NotImplementedError("Unexpected {} references from {}".format(len(refs), fct_addr.add(8)))
    ref = refs[0]
    if ref.getReferenceType() not in {ghidra.program.model.symbol.FlowType.COMPUTED_CALL, ghidra.program.model.symbol.FlowType.COMPUTED_CALL_TERMINATOR}:
        raise NotImplementedError("Unexpected reference type {} from {}".format(ref.getReferenceType(), fct_addr.add(8)))
    called_fct = currentProgram.listing.getFunctionContaining(ref.getToAddress())
    if called_fct:
        fct.setThunkedFunction(called_fct)

fct_mgr = currentProgram.getFunctionManager()
for fct in fct_mgr.getFunctions(True):
    fix_plt_function(fct)
