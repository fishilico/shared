# Define functions which are useful in Ghira Python scripts
#
# These functions can be directly copy-pasted in Ghidra's Python windows
#
# Some snippets:
# - https://github.com/HackOvert/GhidraSnippets
#
# Some links to do constant analysis to recover function args:
# - https://github.com/astrelsky/ghidra_scripts/blob/ac3caaf7762f59a72bfeef8e24cbc8d1eda00657/PrintfSigOverrider.java#L292-L317
#   instantiate Ghidra's constant propagation analysis engine
# - https://github.com/schlafwandler/ghidra_ExportToX64dbg/blob/master/ExportToX64dbg.py
#   uses the decompiler
import re


# Some types
char_t = ghidra.program.model.data.CharDataType.dataType
byte_t = ghidra.program.model.data.ByteDataType.dataType
uint_t = ghidra.program.model.data.UnsignedIntegerDataType.dataType
void_t = ghidra.program.model.data.VoidDataType.dataType
void_p_t = ghidra.program.model.data.PointerDataType(void_t)


def get_pc_bitlen():
    """Get the number of bits of the Program Counter"""
    currentProgram.getLanguage().getProgramCounter().getBitLength()


def get_string_at(addr):
    """Get the NUL-terminated string at the given address"""
    if isinstance(addr, (int, long)):
        addr = toAddr(addr)
    data = getDataAt(addr)
    if data is not None:
        return "".join(chr(d) for d in data.getBytes()).split("\0", 1)[0]
    result = []
    while True:
        new_char = getByte(addr.add(len(result)))
        if new_char == 0:
            return "".join(result)
        result.append(chr(new_char))


def get_data_type(type_name):
    """Get a data type from its name"""
    data_types = getDataTypes(type_name)
    if data_types:
        if len(data_types) != 1:
            raise ValueError("Error: data type {} matches {} types".format(type_name, len(data_types)))
        return data_types[0]
    # Create array types automatically
    # char[10][20] is an array of 10 char[20], so make sure the parsing is done in the right order
    if "[" in type_name:
        matches = re.match(r"^([^\[]*)\[([0-9]+)\]([0-9\[\]]*)$", type_name)
        if matches:
            base_type = get_data_type(matches.group(1) + matches.group(3))
            count = int(matches.group(2))
            return ghidra.program.model.data.ArrayDataType(base_type, count, base_type.getLength())
    raise ValueError("Error: unknown data type {}".format(type_name))


def import_data_type(type_name, arcname="", category="/"):
    """Import data type from an archive"""
    data_types = getDataTypes(type_name)
    if not data_types:
        # Create array types automatically
        if "[" in type_name:
            matches = re.match(r"^(.*)\[([0-9]+)\]$", type_name)
            if matches:
                base_type = import_data_type(matches.group(1), arcname=arcname, category=category)
                count = int(matches.group(2))
                return ghidra.program.model.data.ArrayDataType(base_type, count, base_type.getLength())
    if not data_types:
        if not arcname:
            raise ValueError("Error: unknown local data type {}".format(type_name))
        print("Importing type {} from {}, category {}".format(type_name, arcname, category))
        dtmgr_svc = state.getTool().getService(ghidra.app.services.DataTypeManagerService)
        common_dtmgr_list = [dtmgr for dtmgr in dtmgr_svc.getDataTypeManagers() if dtmgr.name == arcname]
        if len(common_dtmgr_list) != 1:
            raise ValueError("Error: unable to find archive {}".format(arcname))
        common_dtmgr = common_dtmgr_list[0]
        datatype = common_dtmgr.getDataType(ghidra.program.model.data.CategoryPath(category), type_name)
        if not datatype:
            raise ValueError("Error: unable to find {} in cat {} from archive {}".format(type_name, category, arcname))
        currentProgram.getDataTypeManager().addDataType(datatype, None)
        data_types = getDataTypes(type_name)
    if len(data_types) != 1:
        raise ValueError("Error: data type {} matches {} types".format(type_name, len(data_types)))
    return data_types[0]


def get_symbol_addr(name):
    """Get the address of a global symbol"""
    symbols = currentProgram.symbolTable.getGlobalSymbols(name)
    if not symbols:
        raise RuntimeError("Symbol {!r} is not defined".format(name))
    if len(symbols) > 1:
        raise RuntimeError("Symbol {!r} is defined {} times!".format(name, len(symbols)))
    return symbols[0].getAddress()


def describe_data_addr(addr, return_none=False):
    """Get the label of a given address"""
    if isinstance(addr, (int, long)):
        addr = toAddr(addr)
    existing_syms = currentProgram.symbolTable.getSymbols(addr)
    primary_sym_names = [sym.getName() for sym in existing_syms if sym.isPrimary()]
    if primary_sym_names:
        return ",".join(primary_sym_names)
    return None if return_none else addr.toString()


def set_label(addr, name, make_primary=True, verbose=True):
    """Set the label of an address, making it the primary symbol"""
    if isinstance(addr, (int, long)):
        addr = toAddr(addr)
    existing_syms = currentProgram.symbolTable.getSymbols(addr)
    existing_sym = [sym for sym in existing_syms if sym.getName() == name]
    if existing_sym:
        assert len(existing_sym) == 1
        if make_primary and not existing_sym[0].isPrimary():
            if verbose:
                print("Making {}@{} primary name".format(name, addr))
            existing_sym[0].setPrimary()
    else:
        if verbose:
            print("Creating label {}@{} (was {})".format(name, addr, ", ".join(sym.getName() for sym in existing_syms)))
        createLabel(addr, name, make_primary)


def set_data_type(addr, new_data_type, force=False, desc=None):
    """Set the type of the data at the given address to a given type (use a description to be verbose)"""
    if isinstance(addr, (int, long)):
        addr = toAddr(addr)
    current_data = getDataAt(addr)
    if current_data is None:
        if desc:
            print("Defining {} data type: {} at {}".format(desc, new_data_type.getName(), addr))
    elif current_data.getDataType().toString() != new_data_type.toString():
        if desc:
            print("Setting {} data type: {} -> {} at {}".format(desc, current_data.getDataType().getName(), new_data_type.getName(), addr))
        removeData(current_data)
    else:
        return
    if force:
        ghidra.program.model.data.DataUtilities.createData(currentProgram, addr, new_data_type, new_data_type.getLength(), False, ghidra.program.model.data.DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
    else:
        createData(addr, new_data_type)


def set_data_type_array(addr, new_data_type, count, force=False, desc=None):
    """Set the type of the data at the given address to an array"""
    if isinstance(addr, (int, long)):
        addr = toAddr(addr)
    array_dt = ghidra.program.model.data.ArrayDataType(new_data_type, count, new_data_type.getLength())
    set_data_type(addr, array_dt, force=force, desc=desc)


def define_memregion(name, addr, size, permissions):
    """Define a memory region
    Example: to define a read-write 64KB area at 0x20000000:
        define_memregion("RAM", 0x20000000, 0x10000, 6)
    """
    ram = currentProgram.getAddressFactory().getAddressSpace("ram")
    mem = currentProgram.getMemory()
    if mem.getBlock(ram.getAddress(addr)) is None:
        print("Creating {} at {:#x}".format(name, addr))
        mem.createUninitializedBlock(name, ram.getAddress(addr), size, False)
    block = mem.getBlock(ram.getAddress(addr))
    if block.start.offset != addr:
        # If the start address is wrong, report an error because the use needs to split the block
        print("Error: block start of {}@{:#x} is not {:#x}".format(block.name, block.start.offset, addr))
        return
    if block.size != size:
        # If the block size is different, report a warning because the user needs to adjust it
        print("Warning block size {}@{:#x} is {:#x} != {:#x}".format(block.name, addr, block.size, size))
    if block.name != name:
        print("Changing block name {}@{:#x} to {}".format(block.name, addr, name))
        block.setName(name)
    if block.flags != permissions:
        print("Changing block permissions {}@{:#x} from {:#x} to {:#x}".format(name, addr, block.flags, permissions))
        block.setPermissions((permissions & 4) != 0, (permissions & 2) != 0, (permissions & 1) != 0)
        block.setVolatile((permissions & 8) != 0)


def define_rwv_memregion(name, addr, size, type_name, arcname="common", category="/"):
    """Define a Read-Write-Volatile memory region
    Example: to define a 4096-byte mapping the top of a 32-bit memory, defined
    in a structure named HW_HIGH_4K:
        define_rwv_memregion("HW_HIGH_4K", 0xfffff000, 0x1000, "HW_HIGH_4K", "common", "/HW_devices")
    The structure can be defined in a "common" datatype archive, in namespace "HW_devices"
    """
    ram = currentProgram.getAddressFactory().getAddressSpace("ram")
    mem = currentProgram.getMemory()
    if mem.getBlock(ram.getAddress(addr)) is None:
        print("Creating {} at {:#x}".format(name, addr))
        mem.createUninitializedBlock(name, ram.getAddress(addr), size, False)
    block = mem.getBlock(ram.getAddress(addr))
    if block.start.offset != addr:
        # If the start address is wrong, report an error because the use needs to split the block
        print("Error: block start of {}@{:#x} is not {:#x}".format(block.name, block.start.offset, addr))
        return
    if block.size != size:
        # If the block size is different, report a warning because the user needs to adjust it
        print("Warning block size {}@{:#x} is {:#x} != {:#x}".format(block.name, addr, block.size, size))
    if block.name != name:
        print("Changing block name {}@{:#x} to {}".format(block.name, addr, name))
        block.setName(name)
    if block.flags != 0xe:
        print("Changing block flags {}@{:#x} from {:#x}".format(name, addr, block.flags))
        block.setPermissions(True, True, False)
        block.setVolatile(True)
    if type_name:
        addr_obj = ram.getAddress(addr)
        data_type = import_data_type(type_name, arcname=arcname, category=category)
        if getDataAt(addr_obj) is None:
            print("Setting type of {:#x} to {}".format(addr, data_type.name))
            createData(ram.getAddress(addr), data_type)
        else:
            set_data_type(addr_obj, data_type, desc=name)


def iterate_table(tbl):
    """Iterate a table from a getDataAt(addr) call, using API from https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Data.html
    This also works with structures, with getFieldName() and getDataType()
    """
    for i in range(tbl.getNumComponents()):
        yield tbl.getComponent(i)


def get_global_function(name):
    """Get the function object from the given name"""
    result = list(getGlobalFunctions(name))
    if len(result) != 1:
        raise RuntimeError("Function {} is defined {} times".format(name, len(result)))
    return result[0]


def get_imported_function(name, maybe=False):
    """Get the function object from the given program import. If maybe=True, return None when the function is not found"""
    sym = currentProgram.symbolTable.getExternalSymbol(name)
    if sym is None:
        if maybe:
            return None
        raise RuntimeError("No external symbol {} found".format(name))
    if sym.getReferenceCount() != 1:
        raise RuntimeError("External symbol {} is referenced {} times".format(name, sym.getReferenceCount()))
    thunk_addr = sym.getReferences()[0].getFromAddress()
    fct = currentProgram.listing.getFunctionAt(thunk_addr)
    if fct is not None:
        return fct
    possible_functions = []
    for ref in currentProgram.referenceManager.getReferencesTo(thunk_addr):
        if ref.getReferenceType() == ghidra.program.model.symbol.FlowType.UNCONDITIONAL_CALL:
            fct = currentProgram.listing.getFunctionContaining(ref.getFromAddress())
            assert fct.name == name, "Unexpected function name: {} for import {}".format(fct, name)
            possible_functions.append(fct)
    if len(possible_functions) != 1:
        raise RuntimeError("Unable to find import function {}: {}".format(name, possible_functions))
    return possible_functions[0]


def iter_all_functions(start_addr=None):
    fct_mgr = currentProgram.getFunctionManager()
    if start_addr is None:
        iterator = fct_mgr.getFunctions(True)  # forward = True
    else:
        iterator = fct_mgr.getFunctions(start_addr, True)
    for fct in iterator:
        yield fct


def iter_called_functions(fct):
    """Enumerate all functions which are called from this function"""
    for body_range in fct.getBody():
        for addr in body_range:
            for ref in currentProgram.referenceManager.getReferencesFrom(addr):
                if ref.getReferenceType() in {ghidra.program.model.symbol.FlowType.UNCONDITIONAL_CALL, ghidra.program.model.symbol.FlowType.COMPUTED_CALL, ghidra.program.model.symbol.FlowType.COMPUTED_CALL_TERMINATOR}:
                    called_fct = currentProgram.listing.getFunctionContaining(ref.getToAddress())
                    if called_fct:
                        yield ref, called_fct


def iter_functions_calling(fct):
    """Get the functions calling the given function, by XRef"""
    for ref in currentProgram.referenceManager.getReferencesTo(fct.getSymbol().getAddress()):
        if ref.getReferenceType() in {ghidra.program.model.symbol.FlowType.UNCONDITIONAL_CALL, ghidra.program.model.symbol.FlowType.COMPUTED_CALL, ghidra.program.model.symbol.FlowType.COMPUTED_CALL_TERMINATOR}:
            calling_fct = currentProgram.listing.getFunctionContaining(ref.getFromAddress())
            if calling_fct:
                yield calling_fct


def describe_fun_addr(addr, with_address=False, return_none=False):
    """Get a description of the given address, like function+0x10"""
    if isinstance(addr, (int, long)):
        addr = toAddr(addr)
    fct = currentProgram.listing.getFunctionContaining(addr)
    if fct is None:
        return None if return_none else addr
    if fct.getEntryPoint() == addr:
        fct_and_off = fct.name
    else:
        fct_and_off = "{}+{:#x}".format(fct.name, addr.getOffset() - fct.getEntryPoint().getOffset())
    return "{} ({})".format(addr, fct_and_off) if with_address else fct_and_off


def rename_fun(fct, name, verbose=True):
    """Rename a function, which was for example obtained through getFunctionAt(toAddr(0x00010000))
    or currentProgram.listing.getFunctionContaining(toAddr(0x00010000))
    """
    if fct and name and fct.getName() != name:
        if verbose:
            print("Renaming function {}@{} -> {}".format(fct, fct.getSymbol().getAddress(), name))
        fct.setName(name, ghidra.program.model.symbol.SourceType.DEFAULT)


def set_fun_signature(fct, fct_sign, force_name=None, verbose=True):
    """Set the signature of the given function"""
    if force_name:
        # Use this name instead of the one in fct_sign
        retval_and_name, args = fct_sign.split("(", 1)
        retval, _ = retval_and_name.rsplit(" ", 1)
        fct_sign = retval + " " + force_name + "(" + args
    signature_parser = ghidra.app.util.parser.FunctionSignatureParser(currentProgram.getDataTypeManager(), None)
    # Identify the new calling convention before parsing the signature, as the parser ignores it
    new_calling_conv = None
    retval_and_name, args = fct_sign.split("(", 1)
    retval_and_calling_conv, name = retval_and_name.rsplit(" ", 1)
    maybe_calling_conv_parts = retval_and_calling_conv.rsplit(" ", 1)
    if len(maybe_calling_conv_parts) == 2:
        maybe_calling_conv = maybe_calling_conv_parts[1]
        if maybe_calling_conv in {"__cdecl", "cdecl", "__fastcall", "fastcall", "__stdcall", "stdcall", "__thiscall", "thiscall"}:
            new_calling_conv = maybe_calling_conv
            new_fct_sign = maybe_calling_conv_parts[0] + " " + name + "(" + args
            assert new_fct_sign == fct_sign.replace(" " + new_calling_conv + " ", " ")
            fct_sign = new_fct_sign
    try:
        new_signature = signature_parser.parse(fct.getSignature(), fct_sign)
    except ghidra.app.util.cparser.C.ParseException:
        print("Error while parsing {!r} for {}".format(fct_sign, fct))
        raise
    if new_calling_conv:
        new_signature.setCallingConvention(new_calling_conv)
    else:
        # Re-use the existing calling convention
        new_signature.setCallingConvention(fct.getCallingConventionName())
    if new_signature != fct.getSignature():
        if verbose:
            print("Setting function signature {}@{} to {}".format(fct, fct.getSymbol().getAddress(), new_signature))
        command = ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
            fct.getSymbol().getAddress(),
            new_signature,
            ghidra.program.model.symbol.SourceType.ANALYSIS)
        if not runCommand(command):
            raise RuntimeError("Failed to run ApplyFunctionSignatureCmd for {}".format(fct_sign))
    if new_calling_conv and new_calling_conv != str(fct.getCallingConvention()):
        if verbose:
            print("Setting function calling convention {}@{} to {}".format(fct, fct.getSymbol().getAddress(), new_calling_conv))
        fct.setCallingConvention(new_calling_conv)


def apply_fun_signature(fct_sign, verbose=True):
    """Apply a function signature, finding the relevant function"""
    fct_name = fct_sign.split("(", 1)[0].split()[-1]
    fct = get_global_function(fct_name)
    set_fun_signature(fct, fct_sign, verbose=verbose)


def apply_imported_fun_signature(fct_sign, verbose=True, maybe=False):
    """Apply a function signature, finding the relevant function"""
    fct_name = fct_sign.split("(", 1)[0].split()[-1]
    fct = get_imported_function(fct_name, maybe=maybe)
    if maybe and fct is None:
        # The function was not imported
        return
    set_fun_signature(fct, fct_sign, verbose=verbose)


def rename_fun_and_apply(fct, fct_sign, verbose=True):
    """Rename and apply a function signature to a function which was identified"""
    fct_name = fct_sign.split("(", 1)[0].split()[-1]
    rename_fun(fct, fct_name, verbose=verbose)
    set_fun_signature(fct, fct_sign, verbose=verbose)


def get_or_create_fun_at(addr, name_or_sign, rename=True, comment=None, verbose=True):
    """Get the function at the given address, or create it if needed"""
    if isinstance(addr, (int, long)):
        addr = toAddr(addr)
    if not name_or_sign:
        # Just create the function, without any name
        fct_sign = None
        fct_name = None
        rename = False
    elif " " in name_or_sign:
        fct_sign = name_or_sign
        fct_name = name_or_sign.split("(", 1)[0].split()[-1]
    else:
        fct_sign = None
        fct_name = name_or_sign
    fct = getFunctionAt(addr)
    if fct is None:
        if verbose:
            print("Creating function {} at {}".format(fct_name, addr))
        disassemble(addr)
        createFunction(addr, fct_name)
    fct = getFunctionAt(addr)
    if fct is None:
        raise ValueError("Unable to get function {} at {}".format(fct_name, addr))
    if rename:
        rename_fun(fct, fct_name, verbose=verbose)
    if fct_sign:
        set_fun_signature(fct, fct_sign, verbose=verbose)
    if comment:
        fct.setComment(comment)
    return fct


def create_fun_at_if_absent(addr, name_or_sign, rename=True, verbose=True):
    """Like get_or_create_fun_at, but without a return value. By default, it renames the function"""
    get_or_create_fun_at(addr, name_or_sign, rename=rename, verbose=verbose)


def init_decomp():
    """Initialize a decompiler instance"""
    decomp = ghidra.app.decompiler.DecompInterface()
    decomp.toggleSyntaxTree(True)
    decomp.toggleCCode(True)
    decomp.openProgram(currentProgram)
    return decomp


def decompile_fun(fct, decomp):
    """Decompile a given function.
    decomp_result.getDecompiledFunction().getC() : C code as string
    decomp_result.getDecompiledFunction().getSignature() : function signature
    decomp_result.getCCodeMarkup() : C nodes
    """
    decomp_result = decomp.decompileFunction(fct, 10000, monitor if "monitor" in globals() else None)
    if not decomp_result.decompileCompleted():
        print("Error while decompiling {}: {}".format(fct, decomp_result.getErrorMessage()))
        raise RuntimeError(decomp_result.getErrorMessage())
    return decomp_result


def print_high_pcode(high_fct):
    """Show the refined P-Code from a High function, for example decompiled using decompile_fun(fct, decomp).getHighFunction()
    Code inspired from https://github.com/NationalSecurityAgency/ghidra/issues/2183#issuecomment-670180624
    """
    if isinstance(high_fct, ghidra.app.decompiler.DecompileResults):
        # Allow using the decompilation result directly
        high_fct = high_fct.getHighFunction()
    for pcodeop in high_fct.getPcodeOps():
        print("{}".format(pcodeop.toString()))


def get_c_statements(fct, decomp):
    """Get all C statements of a given function. Use getMinAddress() to get the address
    https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html
    """
    decomp_result = decompile_fun(fct, decomp)
    result = []
    def _walker(node):  # noqa
        if isinstance(node, ghidra.app.decompiler.ClangStatement):
            result.append(node)
        else:
            for i in range(node.numChildren()):
                _walker(node.Child(i))
    _walker(decomp_result.getCCodeMarkup())
    return result


def varnode_propagate_unique(varnode):
    """Propagate the Unique definition of a decompiler varnode (either from C statements or from high function pcodeOps)
    cf. https://github.com/NationalSecurityAgency/ghidra/discussions/3711#discussioncomment-2138061
    """
    if varnode.isUnique():
        # Retrieve the pcodeop defining the unique
        pcodeop = varnode.getDef()
        if pcodeop.getMnemonic() == "COPY" and pcodeop.numInputs == 1:
            # Match a direct copy of some other varnode
            return varnode_propagate_unique(pcodeop.getInput(0))
        if pcodeop.getMnemonic() == "CAST" and pcodeop.numInputs == 1:
            # Match a type cast of some other varnode
            return varnode_propagate_unique(pcodeop.getInput(0))
        if (
                pcodeop.getMnemonic() == "PTRSUB" and
                pcodeop.numInputs == 2 and
                pcodeop.getInput(0).isConstant() and
                pcodeop.getInput(0).getOffset() == 0
            ):
            # Match a Pointer subtraction with zero:
            #    (unique, 0x10000000, 8) PTRSUB (const, 0x0, 8) , (const, 0x1234, 8)
            # => (const, 0x1234, 8)
            return varnode_propagate_unique(pcodeop.getInput(1))
    return varnode


def varnode_get_constant(varnode):
    """Retrieve the constant value from a varnode"""
    if varnode.isUnique():
        varnode = varnode_propagate_unique(varnode)
    if varnode.isConstant():
        return varnode.getOffset()
    raise ValueError("Varnode does not contain a constant: {!r}".format(varnode))


def varnode_get_constant_ptr(varnode):
    """Retrieve the constant pointer from a varnode"""
    return toAddr(varnode_get_constant(varnode))


def c_sta_get_funcall_name_and_args(sta):
    """Return the name of the called function and its arguments, if the C statement is about a function call.
    The arguments are returned as a list of list of tokens from module ghidra.app.decompiler
    https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/package-summary.html
    """
    pos = 0
    num_children = sta.numChildren()
    if num_children < 4:
        return None, None
    if (
            isinstance(sta.Child(pos), ghidra.app.decompiler.ClangVariableToken) and
            isinstance(sta.Child(pos + 1), ghidra.app.decompiler.ClangSyntaxToken) and sta.Child(1).getText() == " " and
            isinstance(sta.Child(pos + 2), ghidra.app.decompiler.ClangOpToken) and sta.Child(2).getText() == "=" and
            isinstance(sta.Child(pos + 3), ghidra.app.decompiler.ClangSyntaxToken) and sta.Child(3).getText() == " "
        ):
        # Match "res = fct(...)"
        pos += 4
        if pos + 5 >= num_children:
            return None, None
    if not isinstance(sta.Child(pos), ghidra.app.decompiler.ClangFuncNameToken):
        # Match "fct(...)"
        return None, None
    fct_name = sta.Child(pos).getText()
    if not fct_name:
        raise ValueError("Function call has uses an empty name at {}: {}".format(pos, sta))
    pos += 1
    if not isinstance(sta.Child(pos), (ghidra.app.decompiler.ClangBreak, ghidra.app.decompiler.ClangSyntaxToken)) or sta.Child(pos).getText() != "":
        raise ValueError("Function call {} has an invalid syntax (unexpected {} {!r} at {})".format(sta, type(sta.Child(pos)), repr(sta.Child(pos)), pos))
    pos += 1
    if not isinstance(sta.Child(pos), ghidra.app.decompiler.ClangSyntaxToken) or sta.Child(pos).getText() != "(":
        raise ValueError("Function call {} has an invalid syntax (unexpected {} {!r} at {})".format(sta, type(sta.Child(pos)), repr(sta.Child(pos)), pos))
    pos += 1
    if pos >= num_children:
        raise ValueError("Function call {} has an invalid syntax ({} >= {})".format(sta, pos, num_children))
    fct_args = []
    while True:
        current_fct_arg = []
        opened_parentheses = 0  # Count parentheses open for example with casts "(byte *)&DAT_00001234"
        while True:
            if isinstance(sta.Child(pos), ghidra.app.decompiler.ClangOpToken) and sta.Child(pos).getText() == ",":
                # End of the current argument
                if not current_fct_arg:
                    raise ValueError("Function call {} has an invalid syntax, empty arg at {}".format(sta, pos))
                fct_args.append(current_fct_arg)
                pos += 1
                if pos >= sta.numChildren():
                    raise ValueError("Function call {} has an invalid syntax ({} >= {})".format(sta, pos, num_children))
                break
            if isinstance(sta.Child(pos), ghidra.app.decompiler.ClangSyntaxToken) and sta.Child(pos).getText() == "(":
                opened_parentheses += 1
            if isinstance(sta.Child(pos), ghidra.app.decompiler.ClangSyntaxToken) and sta.Child(pos).getText() == ")":
                if opened_parentheses > 0:
                    opened_parentheses -= 1
                else:
                    # End of the all arguments
                    if not current_fct_arg:
                        # No argument, which is ok if we were expecting the first argument
                        if fct_args:
                            raise ValueError("Function call {} has an invalid syntax, empty last arg at {}".format(sta, pos))
                    else:
                        fct_args.append(current_fct_arg)
                    pos += 1
                    if pos != sta.numChildren():
                        raise ValueError("Function call {} has trailing children ({} < {})".format(sta, pos, num_children))
                    return fct_name, fct_args
            # Add token to the current argument, if it is not empty
            if isinstance(sta.Child(pos), (ghidra.app.decompiler.ClangBreak, ghidra.app.decompiler.ClangSyntaxToken)) and sta.Child(pos).getText() == "":
                pass
            else:
                current_fct_arg.append(sta.Child(pos))
            pos += 1
            if pos >= num_children:
                raise ValueError("Function call {} has an invalid syntax ({} >= {})".format(sta, pos, num_children))


def c_sta_get_funcall_name(sta):
    """Return the name of the called function, if the C statement is about a function call"""
    name, _ = c_sta_get_funcall_name_and_args(sta)
    return name


def c_sta_get_funcall_arg_const_int(arg_tokens, unsigned=False):
    """Return the constant integer from the tokens retrieved from c_sta_get_funcall_name_and_args"""
    if len(arg_tokens) != 1:
        raise ValueError("Argument for const int contains multiple tokens: {!r}".format(arg_tokens))
    scalar = arg_tokens[0].getScalar()
    if scalar is None:
        raise ValueError("Argument for const int is not a scalar: {!r}".format(arg_tokens))
    return scalar.getUnsignedValue() if unsigned else scalar.getValue()


def c_sta_get_funcall_arg_ptr(arg_tokens):
    """Return the pointer from the tokens retrieved from c_sta_get_funcall_name_and_args"""
    if len(arg_tokens) == 1 and isinstance(arg_tokens[0], ghidra.app.decompiler.ClangVariableToken):
        # Match a varnode directly
        varnode = arg_tokens[0].getVarnode()
        if varnode is None:
            raise ValueError("Unexpected empty varnode for {!r}".format(arg_tokens[0]))
        return toAddr(varnode_get_constant(varnode))
    if (
            len(arg_tokens) == 2 and
            isinstance(arg_tokens[0],ghidra.app.decompiler.ClangOpToken) and
            arg_tokens[0].getText() == "&" and
            isinstance(arg_tokens[1], ghidra.app.decompiler.ClangVariableToken)
        ):
        # Match "&DAT_00001234"
        pcodeop = arg_tokens[1].getPcodeOp()
        if (
                pcodeop.getMnemonic() == "PTRSUB" and
                pcodeop.getInput(0).isConstant() and
                pcodeop.getInput(0).getOffset() == 0 and
                pcodeop.getInput(1).isConstant()
            ):
            return toAddr(pcodeop.getInput(1).getOffset())
    raise ValueError("Unexpected argument for pointer: {!r}".format(arg_tokens))


def c_sta_call_get_arg_string(arg_tokens):
    """Return the string from the tokens retrieved from c_sta_get_funcall_name_and_args"""
    return get_string_at(c_sta_get_funcall_arg_ptr(arg_tokens))
