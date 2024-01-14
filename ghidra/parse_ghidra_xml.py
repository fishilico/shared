#!/usr/bin/env python3
"""Parse Ghidra XML export files"""
import argparse
import re
import sys
import xml.etree.ElementTree
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, TextIO, Tuple, Union

YESNO_BOOL: Mapping[str, bool] = {
    "n": False,
    "y": True,
}


@dataclass
class DTStructMember:
    """Structure and Union member in a Ghidra project"""

    name: str
    offset: int
    size: int
    datatype: str
    dtnamespace: str
    comments: List[str]


@dataclass
class DTStruct:
    """Structure data type in a Ghidra project"""

    name: str
    namespace: str
    size: int
    is_varlen: bool
    members: List[DTStructMember]
    comments: List[str]


@dataclass
class DTUnion:
    """Union data type in a Ghidra project"""

    name: str
    namespace: str
    size: int
    members: List[DTStructMember]
    comments: List[str]


@dataclass
class DTFunc:
    """Function data type in a Ghidra project"""

    name: str
    namespace: str
    typeinfo: str
    comments: List[str]


@dataclass
class DTEnumEntry:
    """Enum entry in a Ghidra project"""

    name: str
    value: int
    comments: List[str]


@dataclass
class DTEnum:
    """Enum data type in a Ghidra project"""

    name: str
    namespace: str
    size: int
    entries: List[DTEnumEntry]
    comments: List[str]


@dataclass
class DTTypedef:
    """Typedef data type in a Ghidra project"""

    name: str
    namespace: str
    datatype: str
    dtnamespace: str
    comments: List[str]


@dataclass
class Symbol:
    """Symbol object in a Ghidra project"""

    address: int
    name: str
    namespace: str
    datatype: Optional[str]
    dtnamespace: Optional[str]
    is_local: bool
    is_user_defined: bool
    is_imported: bool
    is_from_analysis: bool
    is_primary: bool


@dataclass
class Function:
    """Function object in a Ghidra project"""

    entrypoint: int
    name: str
    is_library: bool
    typeinfo: Optional[str]


def produce_comments(comments: List[str], fout: TextIO, indent: str = "") -> None:
    """Produce C comments"""
    if not comments:
        return
    for com in comments:
        print(f"{indent}/* {com} */", file=fout)


@dataclass
class GhidraProject:
    """Exported information from a Ghidra project"""

    datatypes: List[Union[DTStruct, DTUnion, DTFunc, DTEnum, DTTypedef]]
    symbols: List[Symbol]
    functions: List[Function]

    def produce_pseudo_c_header(self, fout: TextIO) -> None:
        """Produce a Pseudo-C header file with datatypes and function prototypes

        As the dependencies between structures is incorrect, this code is not expected to compile.
        If you want real C code, you can use "Export Program" with format "C/C++"
        """
        print("/*", file=fout)
        print(" * Datatypes", file=fout)
        print(" */", file=fout)
        print("", file=fout)
        for dt in self.datatypes:
            if isinstance(dt, DTStruct):
                varlen_desc = " has variable length" if dt.is_varlen else ""
                print(f"// {dt.namespace}/{dt.name}: {dt.size:#x} bytes{varlen_desc}", file=fout)
                produce_comments(dt.comments, fout)
                print(f"typedef struct {dt.name} {{", file=fout)
                for member in dt.members:
                    produce_comments(member.comments, fout, indent="    ")
                    mem_name = member.name or f"__field_{member.offset:#x}__"
                    mem_dt = member.datatype
                    print(f"    /* {member.offset:#6x}, {member.size:#6x} */ {mem_dt} {mem_name};", file=fout)
                print(f"}} {dt.name};", file=fout)
            elif isinstance(dt, DTUnion):
                print(f"// {dt.namespace}/{dt.name}: {dt.size:#x} bytes", file=fout)
                produce_comments(dt.comments, fout)
                print(f"typedef union {dt.name} {{", file=fout)
                for member in dt.members:
                    produce_comments(member.comments, fout, indent="    ")
                    mem_name = member.name or f"__field_{member.offset:#x}__"
                    mem_dt = member.datatype
                    print(f"    /* {member.offset:#6x}, {member.size:#6x} */ {mem_dt} {mem_name};", file=fout)
                print(f"}} {dt.name};", file=fout)
            elif isinstance(dt, DTFunc):
                print(f"// {dt.namespace}/{dt.name}: function definition type", file=fout)
                produce_comments(dt.comments, fout)
                print(f"typedef {dt.typeinfo};", file=fout)
            elif isinstance(dt, DTEnum):
                print(f"// {dt.namespace}/{dt.name}: {dt.size} bytes", file=fout)
                produce_comments(dt.comments, fout)
                print(f"typedef enum {dt.name} {{", file=fout)
                for entry in dt.entries:
                    produce_comments(entry.comments, fout, indent="    ")
                    hex_value = f"{{:#{dt.size * 2 + 2}x}}".format(entry.value)
                    print(f"    /* {hex_value} */ {entry.name} = {entry.value};", file=fout)
                print(f"}} {dt.name};", file=fout)
            elif isinstance(dt, DTTypedef):
                print(f"// {dt.namespace}/{dt.name}: typedef to {dt.dtnamespace}/{dt.datatype}", file=fout)
                produce_comments(dt.comments, fout)
                print(f"typedef {dt.datatype} {dt.name};", file=fout)
            else:
                raise NotImplementedError(repr(dt))
            print("", file=fout)

        print("/*", file=fout)
        print(" * Functions", file=fout)
        print(" */", file=fout)
        print("", file=fout)
        for fct in self.functions:
            if fct.typeinfo:
                print(f"// {fct.name} at {fct.entrypoint:#x}", file=fout)
                print(f"{fct.typeinfo};", file=fout)

    def produce_python_script(self, fout: TextIO) -> None:
        """Produce a Python script for Ghidra"""
        for sym in self.symbols:
            # Ignore switch/case labels
            if sym.is_from_analysis and re.match(r"^switchD_[0-9a-f]+::$", sym.namespace):
                if sym.name == "switchD" or re.match(r"^(case|switchdata)D_[0-9a-f]+$", sym.name):
                    continue

            # Ignore debugging symbols like cie_00202207 and fde_00202207
            if sym.is_from_analysis and not sym.namespace and re.match(r"^(cie|fde)_[0-9a-f]+$", sym.name):
                continue

            maybe_comment_prefix = ""
            comment_parts = []
            if sym.is_user_defined:
                comment_parts.append("user-defined")
            if sym.is_imported:
                maybe_comment_prefix = "# "
                comment_parts.append("imported")
            if sym.is_from_analysis:
                comment_parts.append("analysis")
            if not sym.is_primary:
                maybe_comment_prefix = "# "
                comment_parts.append("non-primary")
            if sym.namespace:
                # Do not create names in specific namespace, for now
                maybe_comment_prefix = "# "
                comment_parts.append("namespace={sym.namespace!r}")

            maybe_comment = f"  # {', '.join(comment_parts)}" if comment_parts else ""
            print(f"{maybe_comment_prefix}set_label(toAddr({sym.address:#x}), {sym.name!r}){maybe_comment}", file=fout)
            if sym.datatype:
                if sym.dtnamespace and sym.dtnamespace != "/":
                    # Do not set data type which are using namespaces
                    print(
                        f"# set_data_type(toAddr({sym.address:#x}), get_data_type({sym.datatype!r}))  # dtnamespace={sym.dtnamespace!r}",  # noqa
                        file=fout,
                    )
                else:
                    print(
                        f"{maybe_comment_prefix}set_data_type(toAddr({sym.address:#x}), get_data_type({sym.datatype!r}))",  # noqa
                        file=fout,
                    )

        print("", file=fout)
        for fct in self.functions:
            if fct.typeinfo:
                print(
                    f"create_fun_at_if_absent(toAddr({fct.entrypoint:#x}), {fct.typeinfo!r})  # {fct.name!r}", file=fout
                )
            elif fct.name == f"FUN_{fct.entrypoint:08x}":
                # Do not rename functions with automatic name
                print(f"create_fun_at_if_absent(toAddr({fct.entrypoint:#x}), None)", file=fout)
            elif re.match(r"^thunk_FUN_[0-9a-f]{8}$", fct.name):
                # Do not rename thunk functions with automatic name
                print(f"create_fun_at_if_absent(toAddr({fct.entrypoint:#x}), None)  # {fct.name!r}", file=fout)
            else:
                print(f"create_fun_at_if_absent(toAddr({fct.entrypoint:#x}), {fct.name!r})", file=fout)


def get_comments_from_xml(item: xml.etree.ElementTree.Element) -> List[str]:
    """Get the comments related to an XML item"""
    result: List[str] = []
    for x_comment in item.findall("REPEATABLE_CMT"):
        if x_comment.text:
            result.append(x_comment.text)
    for x_comment in item.findall("REGULAR_CMT"):
        if x_comment.text:
            result.append(x_comment.text)
    try:
        com = item.attrib["COMMENT"]
    except KeyError:
        pass
    else:
        if com:
            result.append(com)
    return result


def get_name_from_xml(item: xml.etree.ElementTree.Element, attr_name: str = "NAME", can_be_empty: bool = False) -> str:
    """Get the name of an XML item"""
    try:
        name: str = item.attrib[attr_name]
    except KeyError:
        if can_be_empty:
            return ""
        raise

    if not can_be_empty:
        assert name
    # Forbid spaces in a name
    assert all(33 <= ord(c) < 127 for c in name), f"Invalid name {name!r}"
    return name


def get_onelinestring_from_xml(item: xml.etree.ElementTree.Element, attr_name: str) -> str:
    """Get the name of an XML item"""
    result: str = item.attrib[attr_name]
    assert result
    # Allow spaces
    assert all(32 <= ord(c) < 127 for c in result), f"Invalid string {result!r}"
    return result


def load_xml_file(file_path: Path) -> GhidraProject:
    """Load a Ghidra XML export file"""
    tree = xml.etree.ElementTree.parse(file_path)
    xml_root = tree.getroot()
    datatypes: List[Union[DTStruct, DTUnion, DTFunc, DTEnum, DTTypedef]] = []
    defined_data: Dict[int, Tuple[str, str]] = {}
    symbols = []
    functions = []

    # Load datatypes
    for x_datatypes in xml_root.findall("DATATYPES"):
        for x_dt in x_datatypes:
            if x_dt.tag == "STRUCTURE":
                members = []
                for x_member in x_dt.findall("MEMBER"):
                    members.append(
                        DTStructMember(
                            name=get_name_from_xml(x_member, can_be_empty=True),
                            offset=int(x_member.attrib["OFFSET"], 0),
                            size=int(x_member.attrib["SIZE"], 0),
                            datatype=get_onelinestring_from_xml(x_member, "DATATYPE"),
                            dtnamespace=get_name_from_xml(x_member, "DATATYPE_NAMESPACE"),
                            comments=get_comments_from_xml(x_member),
                        )
                    )
                datatypes.append(
                    DTStruct(
                        name=get_name_from_xml(x_dt),
                        namespace=get_name_from_xml(x_dt, "NAMESPACE"),
                        size=int(x_dt.attrib["SIZE"], 0),
                        is_varlen=YESNO_BOOL[x_dt.attrib.get("VARIABLE_LENGTH", "n")],
                        members=members,
                        comments=get_comments_from_xml(x_dt),
                    )
                )
            elif x_dt.tag == "UNION":
                members = []
                for x_member in x_dt.findall("MEMBER"):
                    members.append(
                        DTStructMember(
                            name=get_name_from_xml(x_member),
                            offset=int(x_member.attrib["OFFSET"], 0),
                            size=int(x_member.attrib["SIZE"], 0),
                            datatype=get_onelinestring_from_xml(x_member, "DATATYPE"),
                            dtnamespace=get_name_from_xml(x_member, "DATATYPE_NAMESPACE"),
                            comments=get_comments_from_xml(x_member),
                        )
                    )
                datatypes.append(
                    DTUnion(
                        name=get_name_from_xml(x_dt),
                        namespace=get_name_from_xml(x_dt, "NAMESPACE"),
                        size=int(x_dt.attrib["SIZE"], 0),
                        members=members,
                        comments=get_comments_from_xml(x_dt),
                    )
                )
            elif x_dt.tag == "FUNCTION_DEF":
                name = get_name_from_xml(x_dt)
                x_rettype = x_dt.find("RETURN_TYPE")
                if x_rettype is not None:
                    fctdef_typeinfo = get_onelinestring_from_xml(x_rettype, "DATATYPE")
                else:
                    fctdef_typeinfo = "undefined"
                fctdef_typeinfo += f" (*{name})("
                for idx_param, x_param in enumerate(x_dt.findall("PARAMETER")):
                    if idx_param:
                        fctdef_typeinfo += ", "
                    fctdef_typeinfo += get_onelinestring_from_xml(x_param, "DATATYPE")
                    param_name = get_name_from_xml(x_param, can_be_empty=True)
                    if param_name:
                        fctdef_typeinfo += f" {param_name}"
                fctdef_typeinfo += ")"
                datatypes.append(
                    DTFunc(
                        name=name,
                        namespace=get_name_from_xml(x_dt, "NAMESPACE"),
                        typeinfo=fctdef_typeinfo,
                        comments=get_comments_from_xml(x_dt),
                    )
                )
            elif x_dt.tag == "ENUM":
                entries = []
                for x_entry in x_dt.findall("ENUM_ENTRY"):
                    entries.append(
                        DTEnumEntry(
                            name=get_name_from_xml(x_entry),
                            value=int(x_entry.attrib["VALUE"], 0),
                            comments=get_comments_from_xml(x_entry),
                        )
                    )
                datatypes.append(
                    DTEnum(
                        name=get_name_from_xml(x_dt),
                        namespace=get_name_from_xml(x_dt, "NAMESPACE"),
                        size=int(x_dt.attrib["SIZE"], 0),
                        entries=entries,
                        comments=get_comments_from_xml(x_dt),
                    )
                )
            elif x_dt.tag == "TYPE_DEF":
                datatypes.append(
                    DTTypedef(
                        name=get_name_from_xml(x_dt),
                        namespace=get_name_from_xml(x_dt, "NAMESPACE"),
                        datatype=get_onelinestring_from_xml(x_dt, "DATATYPE"),
                        dtnamespace=get_name_from_xml(x_dt, "DATATYPE_NAMESPACE"),
                        comments=get_comments_from_xml(x_dt),
                    )
                )
            else:
                raise NotImplementedError("Unknown data type {x_dt} with {x_dt.attrib}")

    # Load defined data
    for x_data_table in xml_root.findall("DATA"):
        for x_defdata in x_data_table.findall("DEFINED_DATA"):
            if ":" in x_defdata.attrib["ADDRESS"]:
                # Ignore overlapping addresses
                continue
            addr = int(x_defdata.attrib["ADDRESS"], 16)
            datatype = get_onelinestring_from_xml(x_defdata, "DATATYPE")
            dtnamespace = get_name_from_xml(x_defdata, "DATATYPE_NAMESPACE")
            assert addr not in defined_data, f"Duplicate defined data at {addr:#x}"
            defined_data[addr] = (datatype, dtnamespace)

    # Load symbols
    for x_symbol_table in xml_root.findall("SYMBOL_TABLE"):
        for x_symbol in x_symbol_table.findall("SYMBOL"):
            sym_type = get_name_from_xml(x_symbol, "TYPE")
            sym_src_type = get_name_from_xml(x_symbol, "SOURCE_TYPE")
            sym_addr_str = x_symbol.attrib["ADDRESS"]
            if sym_addr_str.startswith("ram:"):
                sym_addr = int(sym_addr_str[4:], 16)
            elif sym_addr_str.startswith(("global:", "table:")):
                # Ignore special symbols used in WebAssembly
                continue
            else:
                sym_addr = int(sym_addr_str, 16)
            sym_defdata = defined_data.get(sym_addr)
            sym = Symbol(
                address=sym_addr,
                name=get_name_from_xml(x_symbol),
                namespace=get_name_from_xml(x_symbol, "NAMESPACE", can_be_empty=True),
                datatype=sym_defdata[0] if sym_defdata else None,
                dtnamespace=sym_defdata[1] if sym_defdata else None,
                is_local={"global": False, "local": True}[sym_type],
                is_user_defined=sym_src_type == "USER_DEFINED",
                is_imported=sym_src_type == "IMPORTED",
                is_from_analysis=sym_src_type == "ANALYSIS",
                is_primary=YESNO_BOOL[x_symbol.attrib["PRIMARY"]],
            )
            symbols.append(sym)

    # Load functions
    for x_functions in xml_root.findall("FUNCTIONS"):
        for x_function in x_functions.findall("FUNCTION"):
            entrypoint_str = x_function.attrib["ENTRY_POINT"]
            if entrypoint_str.startswith("ram:"):
                entrypoint = int(entrypoint_str[4:], 16)
            else:
                entrypoint = int(entrypoint_str, 16)
            x_typeinfo = x_function.find("TYPEINFO_CMT")
            if x_typeinfo is not None:
                fct_typeinfo = x_typeinfo.text
                assert fct_typeinfo
                assert all(32 <= ord(c) < 127 for c in fct_typeinfo), f"Invalid typeinfo {fct_typeinfo!r}"
            else:
                fct_typeinfo = None
            fct = Function(
                entrypoint=entrypoint,
                name=get_name_from_xml(x_function),
                is_library=YESNO_BOOL[x_function.attrib["LIBRARY_FUNCTION"]],
                typeinfo=fct_typeinfo,
            )
            functions.append(fct)

    return GhidraProject(
        datatypes=datatypes,
        symbols=symbols,
        functions=functions,
    )


def open_output_text(file_path: Path) -> TextIO:
    """Open a text file for writing. If "-", use stdout"""
    if str(file_path) == "-":
        return sys.stdout
    return file_path.open("w")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse a Ghidra XML export file")
    parser.add_argument("file", metavar="GHIDRA_FILE", type=Path, help="Ghidra XML export file")
    parser.add_argument(
        "-H", "--header", type=Path, help="Produce a pseudo-C header file with datatypes and defined functions"
    )
    parser.add_argument(
        "-p", "--python", type=Path, help="Produce a Python script for Ghidra, which redefines functions and data"
    )
    args = parser.parse_args()

    prj = load_xml_file(args.file)
    if args.header:
        with open_output_text(args.header) as fout:
            prj.produce_pseudo_c_header(fout)
    if args.python:
        with open_output_text(args.python) as fout:
            prj.produce_python_script(fout)
