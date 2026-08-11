#!/usr/bin/env python3
"""
Proto_Peek — Protocol Buffer inspector.
Parse .proto files, decode raw protobuf, inspect field values.
Zero dependencies. Pure Python stdlib.
"""

import argparse
import json
import os
import re
import struct
import sys
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple, Union

__version__ = "1.0.0"

# ──────────────────────────────────────────────
#  Protobuf Wire Types
# ──────────────────────────────────────────────
WIRE_VARINT = 0
WIRE_64BIT = 1
WIRE_LENGTH_DELIMITED = 2
WIRE_32BIT = 5

WIRE_TYPE_NAMES = {
    0: "varint",
    1: "64-bit",
    2: "length-delimited",
    5: "32-bit",
}

# Field label constants
LABEL_OPTIONAL = "optional"
LABEL_REQUIRED = "required"
LABEL_REPEATED = "repeated"

# Proto scalar types mapping to wire types
SCALAR_TYPES = {
    "int32": WIRE_VARINT,
    "int64": WIRE_VARINT,
    "uint32": WIRE_VARINT,
    "uint64": WIRE_VARINT,
    "sint32": WIRE_VARINT,
    "sint64": WIRE_VARINT,
    "bool": WIRE_VARINT,
    "enum": WIRE_VARINT,
    "fixed32": WIRE_32BIT,
    "fixed64": WIRE_64BIT,
    "sfixed32": WIRE_32BIT,
    "sfixed64": WIRE_64BIT,
    "float": WIRE_32BIT,
    "double": WIRE_64BIT,
    "string": WIRE_LENGTH_DELIMITED,
    "bytes": WIRE_LENGTH_DELIMITED,
}

# Map from proto scalar type to Python struct format for fixed-size types
FIXED_FORMATS = {
    "fixed32": "<I",
    "fixed64": "<Q",
    "sfixed32": "<i",
    "sfixed64": "<q",
    "float": "<f",
    "double": "<d",
}


# ──────────────────────────────────────────────
#  .proto File Parser (regex-based)
# ──────────────────────────────────────────────


class ProtoField:
    """A single field in a protobuf message."""

    def __init__(
        self,
        name: str,
        number: int,
        type_name: str,
        label: str = LABEL_OPTIONAL,
        is_map: bool = False,
        map_key_type: str = "",
        map_value_type: str = "",
    ):
        self.name = name
        self.number = number
        self.type_name = type_name
        self.label = label
        self.is_map = is_map
        self.map_key_type = map_key_type
        self.map_value_type = map_value_type

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "number": self.number,
            "type": self.type_name,
            "label": self.label,
        }
        if self.is_map:
            d["map_key_type"] = self.map_key_type
            d["map_value_type"] = self.map_value_type
        return d

    def __repr__(self):
        if self.is_map:
            return (
                f"map<{self.map_key_type}, {self.map_value_type}> "
                f"{self.name} = {self.number}"
            )
        return f"{self.label} {self.type_name} {self.name} = {self.number}"


class ProtoEnumValue:
    """A value inside a protobuf enum."""

    def __init__(self, name: str, number: int):
        self.name = name
        self.number = number

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "number": self.number}


class ProtoEnum:
    """A protobuf enum definition."""

    def __init__(self, name: str, values: List[ProtoEnumValue]):
        self.name = name
        self.values = values

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "values": [v.to_dict() for v in self.values],
        }


class ProtoMessage:
    """A protobuf message definition."""

    def __init__(
        self,
        name: str,
        fields: List[ProtoField],
        nested_messages: List["ProtoMessage"],
        nested_enums: List[ProtoEnum],
    ):
        self.name = name
        self.fields = fields
        self.nested_messages = nested_messages
        self.nested_enums = nested_enums

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "fields": [f.to_dict() for f in self.fields],
            "nested_messages": [m.to_dict() for m in self.nested_messages],
            "nested_enums": [e.to_dict() for e in self.nested_enums],
        }


class ProtoServiceMethod:
    """A single RPC method in a service."""

    def __init__(self, name: str, input_type: str, output_type: str):
        self.name = name
        self.input_type = input_type
        self.output_type = output_type

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "input_type": self.input_type,
            "output_type": self.output_type,
        }


class ProtoService:
    """A protobuf service definition."""

    def __init__(self, name: str, methods: List[ProtoServiceMethod]):
        self.name = name
        self.methods = methods

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "methods": [m.to_dict() for m in self.methods],
        }


class ProtoFile:
    """Parsed representation of a .proto file."""

    def __init__(
        self,
        syntax: str = "proto3",
        package: str = "",
        imports: Optional[List[str]] = None,
        messages: Optional[List[ProtoMessage]] = None,
        enums: Optional[List[ProtoEnum]] = None,
        services: Optional[List[ProtoService]] = None,
        options: Optional[Dict[str, str]] = None,
    ):
        self.syntax = syntax
        self.package = package
        self.imports = imports or []
        self.messages = messages or []
        self.enums = enums or []
        self.services = services or []
        self.options = options or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "syntax": self.syntax,
            "package": self.package,
            "imports": self.imports,
            "messages": [m.to_dict() for m in self.messages],
            "enums": [e.to_dict() for e in self.enums],
            "services": [s.to_dict() for s in self.services],
            "options": self.options,
        }

    def find_message(self, name: str) -> Optional[ProtoMessage]:
        """Find a top-level or nested message by name."""
        for msg in self.messages:
            if msg.name == name:
                return msg
            # Check nested
            result = _find_nested_message(msg, name)
            if result:
                return result
        return None

    def find_enum(self, name: str) -> Optional[ProtoEnum]:
        """Find a top-level or nested enum by name."""
        for enum in self.enums:
            if enum.name == name:
                return enum
        for msg in self.messages:
            result = _find_nested_enum(msg, name)
            if result:
                return result
        return None

    def resolve_type(self, type_name: str) -> str:
        """Resolve a short type name to its fully qualified form."""
        if type_name in SCALAR_TYPES:
            return type_name
        if "." in type_name:
            return type_name.lstrip(".")
        if self.package:
            return f"{self.package}.{type_name}"
        return type_name


def _find_nested_message(msg: ProtoMessage, name: str) -> Optional[ProtoMessage]:
    for nested in msg.nested_messages:
        if nested.name == name:
            return nested
        result = _find_nested_message(nested, name)
        if result:
            return result
    return None


def _find_nested_enum(msg: ProtoMessage, name: str) -> Optional[ProtoEnum]:
    for enum in msg.nested_enums:
        if enum.name == name:
            return enum
    for nested in msg.nested_messages:
        result = _find_nested_enum(nested, name)
        if result:
            return result
    return None


def _strip_comments(text: str) -> str:
    """Remove C-style // and /* */ comments from proto source."""
    # Remove /* ... */ comments
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    # Remove // line comments (but not http://)
    lines = []
    for line in text.split("\n"):
        in_string = False
        result = []
        i = 0
        while i < len(line):
            ch = line[i]
            if ch == '"' and (i == 0 or line[i - 1] != "\\"):
                in_string = not in_string
                result.append(ch)
                i += 1
            elif ch == "/" and not in_string and i + 1 < len(line) and line[i + 1] == "/":
                break  # rest of line is comment
            else:
                result.append(ch)
                i += 1
        lines.append("".join(result))
    return "\n".join(lines)


def parse_proto_file(filepath: str) -> ProtoFile:
    """Parse a .proto file into a ProtoFile structure."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    content = _strip_comments(content)

    proto_file = ProtoFile()

    # Parse syntax
    syntax_match = re.search(r'syntax\s*=\s*"([^"]+)"', content)
    if syntax_match:
        proto_file.syntax = syntax_match.group(1)

    # Parse package
    package_match = re.search(r"package\s+([\w.]+)\s*;", content)
    if package_match:
        proto_file.package = package_match.group(1)

    # Parse imports
    for m in re.finditer(r'import\s+"([^"]+)"\s*;', content):
        proto_file.imports.append(m.group(1))
    for m in re.finditer(r'import\s+"([^"]+)"\s*;', content):
        pass  # Already handled above

    # Parse options at file level
    for m in re.finditer(r'option\s+(\w+)\s*=\s*"([^"]*)"\s*;', content):
        proto_file.options[m.group(1)] = m.group(2)

    # Find all top-level blocks: message, enum, service
    # We need to handle nested blocks properly — track brace depth
    blocks = _extract_top_level_blocks(content)
    for block in blocks:
        _parse_block(block, proto_file, proto_file)

    return proto_file


def _extract_top_level_blocks(content: str) -> List[Tuple[str, str, str]]:
    """
    Extract top-level message/enum/service blocks.
    Returns list of (block_type, block_name, block_body).
    """
    blocks = []
    # Remove the file-level declarations we've already parsed
    stripped = re.sub(r'\bsyntax\s*=\s*"[^"]*"\s*;', "", content)
    stripped = re.sub(r"\bpackage\s+[\w.]+\s*;", "", stripped)
    stripped = re.sub(r'\bimport\s+"[^"]*"\s*;', "", stripped)
    stripped = re.sub(r'\boption\s+\w+\s*=\s*"[^"]*"\s*;', "", stripped)

    pos = 0
    while pos < len(stripped):
        # Find next message, enum, or service keyword
        m = re.search(r"\b(message|enum|service)\s+(\w+)\s*\{", stripped[pos:])
        if not m:
            break
        block_type = m.group(1)
        block_name = m.group(2)
        start = pos + m.end() - 1  # position of the opening brace
        # Find matching closing brace
        depth = 1
        i = start + 1
        in_string = False
        while i < len(stripped) and depth > 0:
            ch = stripped[i]
            if ch == '"' and (i == 0 or stripped[i - 1] != "\\"):
                in_string = not in_string
            elif not in_string:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
            i += 1
        end = i  # position after closing brace
        body = stripped[start + 1 : end - 1]
        blocks.append((block_type, block_name, body))
        pos = end

    return blocks


def _parse_block(
    block: Tuple[str, str, str],
    proto_file: ProtoFile,
    parent: Union[ProtoFile, ProtoMessage],
):
    """Parse a single block (message/enum/service) and recurse into nested ones."""
    block_type, block_name, body = block

    if block_type == "enum":
        values = _parse_enum_body(body)
        enum = ProtoEnum(block_name, values)
        if isinstance(parent, ProtoFile):
            proto_file.enums.append(enum)
        else:
            parent.nested_enums.append(enum)

    elif block_type == "message":
        fields, nested_msgs, nested_enums = _parse_message_body(body, proto_file)
        msg = ProtoMessage(block_name, fields, nested_msgs, nested_enums)
        if isinstance(parent, ProtoFile):
            proto_file.messages.append(msg)
        else:
            parent.nested_messages.append(msg)

    elif block_type == "service":
        methods = _parse_service_body(body)
        svc = ProtoService(block_name, methods)
        proto_file.services.append(svc)


def _parse_enum_body(body: str) -> List[ProtoEnumValue]:
    """Parse enum values from an enum body."""
    values = []
    # Remove option lines
    cleaned = re.sub(r"\boption\s+[^;]+;", "", body)
    # Find all value assignments
    for m in re.finditer(r"(\w+)\s*=\s*(-?\d+)\s*;", cleaned):
        values.append(ProtoEnumValue(m.group(1), int(m.group(2))))
    return values


def _parse_message_body(
    body: str, proto_file: ProtoFile
) -> Tuple[List[ProtoField], List[ProtoMessage], List[ProtoEnum]]:
    """Parse a message body: fields, nested messages, nested enums."""
    fields: List[ProtoField] = []
    nested_msgs: List[ProtoMessage] = []
    nested_enums: List[ProtoEnum] = []

    # Extract nested blocks first
    nested_blocks = _extract_top_level_blocks(body)
    for nb in nested_blocks:
        _parse_block(nb, proto_file, ProtoMessage("_temp", [], [], []))
        # Re-extract from the right parent — hack but functional
        pass

    # Re-parse properly: extract nested blocks and remaining field lines
    remaining = body
    for block_type, block_name, block_body in nested_blocks:
        # Remove the block from remaining
        pattern = re.escape(f"{block_type} {block_name} {{")
        remaining = re.sub(pattern + r".*?" + re.escape("}"), "", remaining, count=1, flags=re.DOTALL)

        if block_type == "enum":
            vals = _parse_enum_body(block_body)
            nested_enums.append(ProtoEnum(block_name, vals))
        elif block_type == "message":
            flds, nms, nes = _parse_message_body(block_body, proto_file)
            nested_msgs.append(ProtoMessage(block_name, flds, nms, nes))

    # Remove oneof blocks
    remaining = re.sub(r"\boneof\s+\w+\s*\{[^}]*\}", "", remaining, flags=re.DOTALL)

    # Remove option lines
    remaining = re.sub(r"\boption\s+[^;]+;", "", remaining)

    # Remove reserved lines
    remaining = re.sub(r"\breserved\s+[^;]+;", "", remaining)

    # Remove extensions
    remaining = re.sub(r"\bextensions\s+[^;]+;", "", remaining)

    # Parse map fields: map<key_type, value_type> name = number;
    map_pattern = r"map\s*<\s*(\w+)\s*,\s*(\w+)\s*>\s+(\w+)\s*=\s*(\d+)\s*;"
    for m in re.finditer(map_pattern, remaining):
        key_type = m.group(1)
        val_type = m.group(2)
        name = m.group(3)
        number = int(m.group(4))
        fields.append(
            ProtoField(
                name=name,
                number=number,
                type_name=f"map<{key_type}, {val_type}>",
                is_map=True,
                map_key_type=key_type,
                map_value_type=val_type,
            )
        )
    # Remove map lines from remaining
    remaining = re.sub(map_pattern, "", remaining)

    # Parse regular fields: [repeated|optional|required] type name = number [options];
    field_pattern = (
        r"(repeated|optional|required)\s+"
        r"([\w.]+)\s+"
        r"(\w+)\s*=\s*(\d+)"
        r"\s*(?:\[[^\]]*\])?\s*;"
    )
    for m in re.finditer(field_pattern, remaining):
        label = m.group(1)
        type_name = m.group(2)
        name = m.group(3)
        number = int(m.group(4))
        fields.append(ProtoField(name=name, number=number, type_name=type_name, label=label))
    # Remove parsed field lines
    remaining = re.sub(field_pattern, "", remaining)

    # Parse fields without explicit label (proto3 defaults to no label keyword)
    no_label_pattern = (
        r"(?<!\w)(?!repeated\s)(?!optional\s)(?!required\s)"
        r"([\w.]+)\s+"
        r"(\w+)\s*=\s*(\d+)"
        r"\s*(?:\[[^\]]*\])?\s*;"
    )
    for m in re.finditer(no_label_pattern, remaining):
        type_name = m.group(1)
        name = m.group(2)
        number = int(m.group(3))
        # Skip common keywords
        if type_name in (
            "message", "enum", "oneof", "map", "reserved", "extensions",
            "extend", "option", "import", "package", "syntax", "service",
            "rpc", "returns", "stream",
        ):
            continue
        if name in ("true", "false", "null"):
            continue
        fields.append(
            ProtoField(
                name=name,
                number=number,
                type_name=type_name,
                label="",  # proto3 default
            )
        )

    return fields, nested_msgs, nested_enums


def _parse_service_body(body: str) -> List[ProtoServiceMethod]:
    """Parse RPC methods from a service body."""
    methods = []
    # rpc MethodName (InputType) returns (OutputType);
    # Also handle streaming: rpc MethodName (stream InputType) returns (stream OutputType);
    pattern = (
        r"rpc\s+(\w+)\s*\(\s*(?:stream\s+)?([\w.]+)\s*\)"
        r"\s*returns\s*\(\s*(?:stream\s+)?([\w.]+)\s*\)"
    )
    for m in re.finditer(pattern, body):
        methods.append(
            ProtoServiceMethod(
                name=m.group(1),
                input_type=m.group(2),
                output_type=m.group(3),
            )
        )
    return methods


# ──────────────────────────────────────────────
#  Protobuf Binary Decoder
# ──────────────────────────────────────────────


def read_varint(data: bytes, offset: int) -> Tuple[int, int]:
    """Read a varint from data at offset. Returns (value, bytes_consumed)."""
    value = 0
    shift = 0
    consumed = 0
    while offset + consumed < len(data):
        byte = data[offset + consumed]
        value |= (byte & 0x7F) << shift
        consumed += 1
        if (byte & 0x80) == 0:
            break
        shift += 7
    return value, consumed


def zigzag_decode(n: int) -> int:
    """Decode a zigzag-encoded signed integer."""
    return (n >> 1) ^ -(n & 1)


def read_fixed(data: bytes, offset: int, size: int) -> Tuple[bytes, int]:
    """Read fixed-size bytes. Returns (raw_bytes, bytes_consumed)."""
    return data[offset : offset + size], size


def decode_field_value(
    wire_type: int,
    data: bytes,
    offset: int,
    field_type: str = "",
) -> Tuple[Any, int]:
    """
    Decode a single field value based on wire type and optional schema type.
    Returns (decoded_value, bytes_consumed).
    """
    if wire_type == WIRE_VARINT:
        value, consumed = read_varint(data, offset)
        # Apply type-specific decoding
        if field_type in ("sint32", "sint64"):
            value = zigzag_decode(value)
        elif field_type == "bool":
            value = bool(value)
        elif field_type in ("int32", "int64", "uint32", "uint64", "enum"):
            pass  # raw varint is fine
        return value, consumed

    elif wire_type == WIRE_64BIT:
        raw, consumed = read_fixed(data, offset, 8)
        if field_type in FIXED_FORMATS:
            value = struct.unpack(FIXED_FORMATS[field_type], raw)[0]
        elif field_type == "fixed64":
            value = struct.unpack("<Q", raw)[0]
        elif field_type == "sfixed64":
            value = struct.unpack("<q", raw)[0]
        elif field_type == "double":
            value = struct.unpack("<d", raw)[0]
        else:
            value = raw.hex()
        return value, consumed

    elif wire_type == WIRE_LENGTH_DELIMITED:
        length, len_consumed = read_varint(data, offset)
        raw, _ = read_fixed(data, offset + len_consumed, length)
        total = len_consumed + length
        if field_type == "string":
            try:
                value = raw.decode("utf-8")
            except UnicodeDecodeError:
                value = raw.hex()
        elif field_type == "bytes":
            value = raw.hex()
        elif field_type and field_type not in SCALAR_TYPES:
            # It's a message type — try to decode nested
            try:
                value = decode_binary(raw, None)
            except Exception:
                value = raw.hex()
        else:
            # Try UTF-8, fallback to hex
            try:
                value = raw.decode("utf-8")
            except UnicodeDecodeError:
                value = raw.hex()
        return value, total

    elif wire_type == WIRE_32BIT:
        raw, consumed = read_fixed(data, offset, 4)
        if field_type in FIXED_FORMATS:
            value = struct.unpack(FIXED_FORMATS[field_type], raw)[0]
        elif field_type == "fixed32":
            value = struct.unpack("<I", raw)[0]
        elif field_type == "sfixed32":
            value = struct.unpack("<i", raw)[0]
        elif field_type == "float":
            value = struct.unpack("<f", raw)[0]
        else:
            value = raw.hex()
        return value, consumed

    else:
        # Unknown wire type
        return None, 0


def decode_binary(
    data: bytes, proto_file: Optional[ProtoFile] = None, message_type: str = ""
) -> Dict[int, Any]:
    """
    Decode a protobuf binary message.
    Returns dict mapping field_number -> value.
    If repeated fields, value is a list.
    """
    result: Dict[int, Any] = OrderedDict()
    schema_fields: Dict[int, ProtoField] = {}
    schema_enums: Dict[str, ProtoEnum] = {}

    if proto_file and message_type:
        msg = proto_file.find_message(message_type)
        if msg:
            for f in msg.fields:
                schema_fields[f.number] = f
            for enum in proto_file.enums:
                schema_enums[enum.name] = enum
            for enum in msg.nested_enums:
                schema_enums[enum.name] = enum

    offset = 0
    while offset < len(data):
        # Read tag (field_number << 3 | wire_type)
        tag, tag_consumed = read_varint(data, offset)
        if tag_consumed == 0:
            break
        offset += tag_consumed
        field_number = tag >> 3
        wire_type = tag & 0x07

        # Get schema info
        field_type = ""
        field_name = ""
        if field_number in schema_fields:
            sf = schema_fields[field_number]
            field_type = sf.type_name
            field_name = sf.name

        value, consumed = decode_field_value(wire_type, data, offset, field_type)
        offset += consumed

        # Build result entry
        entry: Dict[str, Any] = OrderedDict()
        entry["field_number"] = field_number
        entry["wire_type"] = WIRE_TYPE_NAMES.get(wire_type, f"unknown({wire_type})")
        if field_name:
            entry["field_name"] = field_name
        if field_type:
            entry["field_type"] = field_type
            if field_type in schema_enums:
                enum_def = schema_enums[field_type]
                for ev in enum_def.values:
                    if ev.number == value:
                        entry["enum_name"] = ev.name
                        break
        entry["value"] = value

        # Handle repeated — use field_number as list
        if field_name and field_name in result:
            existing = result[field_name]
            if isinstance(existing, list):
                existing.append(entry)
            else:
                result[field_name] = [existing, entry]
        else:
            key = field_name if field_name else str(field_number)
            result[key] = entry

    return result


# ──────────────────────────────────────────────
#  CLI Subcommands
# ──────────────────────────────────────────────


def cmd_parse(args):
    """Parse a .proto file and print its structure."""
    proto_file = parse_proto_file(args.file)

    if args.format == "json":
        print(json.dumps(proto_file.to_dict(), indent=2, default=str))
        return

    # Text output
    print(f"Syntax: {proto_file.syntax}")
    if proto_file.package:
        print(f"Package: {proto_file.package}")

    if proto_file.imports:
        print(f"\nImports ({len(proto_file.imports)}):")
        for imp in proto_file.imports:
            print(f"  - {imp}")

    if proto_file.options:
        print(f"\nOptions:")
        for k, v in proto_file.options.items():
            print(f"  {k} = \"{v}\"")

    if proto_file.enums:
        print(f"\n── Enums ({len(proto_file.enums)}) ──")
        for enum in proto_file.enums:
            print(f"\n  enum {enum.name} {{")
            for v in enum.values:
                print(f"    {v.name} = {v.number};")
            print(f"  }}")

    if proto_file.messages:
        print(f"\n── Messages ({len(proto_file.messages)}) ──")
        for msg in proto_file.messages:
            _print_message(msg, indent=0)

    if proto_file.services:
        print(f"\n── Services ({len(proto_file.services)}) ──")
        for svc in proto_file.services:
            print(f"\n  service {svc.name} {{")
            for method in svc.methods:
                print(f"    rpc {method.name} ({method.input_type}) returns ({method.output_type});")
            print(f"  }}")


def _print_message(msg: ProtoMessage, indent: int = 0):
    """Pretty-print a message and its nested types."""
    prefix = "  " * indent
    print(f"\n{prefix}message {msg.name} {{")

    for field in msg.fields:
        if field.is_map:
            print(
                f"{prefix}  map<{field.map_key_type}, {field.map_value_type}> "
                f"{field.name} = {field.number};"
            )
        elif field.label:
            print(f"{prefix}  {field.label} {field.type_name} {field.name} = {field.number};")
        else:
            print(f"{prefix}  {field.type_name} {field.name} = {field.number};")

    for enum in msg.nested_enums:
        print(f"{prefix}  enum {enum.name} {{")
        for v in enum.values:
            print(f"{prefix}    {v.name} = {v.number};")
        print(f"{prefix}  }}")

    for nested in msg.nested_messages:
        _print_message(nested, indent + 1)

    print(f"{prefix}}}")


def cmd_fields(args):
    """List fields of a specific message type."""
    proto_file = parse_proto_file(args.file)
    msg = proto_file.find_message(args.message_type)

    if not msg:
        print(f"Error: message type '{args.message_type}' not found in {args.file}", file=sys.stderr)
        sys.exit(1)

    fields_list = []
    for f in msg.fields:
        fields_list.append(f.to_dict())

    if args.format == "json":
        print(json.dumps(fields_list, indent=2))
        return

    if not fields_list:
        print(f"Message '{args.message_type}' has no fields.")
        return

    print(f"Fields of message '{args.message_type}':")
    print(f"  {'Name':<20} {'Number':>6}  {'Type':<16} {'Label':<10}")
    print(f"  {'─' * 20} {'─' * 6}  {'─' * 16} {'─' * 10}")
    for f in fields_list:
        print(
            f"  {f['name']:<20} {f['number']:>6}  "
            f"{f['type']:<16} {f.get('label', ''):<10}"
        )


def cmd_decode(args):
    """Decode a protobuf binary file."""
    with open(args.file, "rb") as f:
        data = f.read()

    proto_file = None
    if args.proto:
        proto_file = parse_proto_file(args.proto)

    result = decode_binary(data, proto_file, args.message_type)

    if args.format == "json":
        print(json.dumps(result, indent=2, default=str))
        return

    if not result:
        print("(empty message or no data decoded)")
        return

    print(f"Decoded '{args.message_type}' ({len(data)} bytes):")
    for key, entry in result.items():
        if isinstance(entry, list):
            for i, e in enumerate(entry):
                _print_decoded_entry(e, idx=f"[{i}]")
        else:
            _print_decoded_entry(entry)


def _print_decoded_entry(entry: Dict[str, Any], idx: str = ""):
    """Print a single decoded field entry."""
    fn = entry.get("field_number", "?")
    fname = entry.get("field_name", "")
    ftype = entry.get("field_type", "")
    wt = entry.get("wire_type", "")
    value = entry.get("value", "")
    enum_name = entry.get("enum_name", "")

    label = fname if fname else f"field_{fn}"
    type_info = f" ({ftype})" if ftype else ""

    if isinstance(value, dict):
        # Nested message
        print(f"  {label}{type_info}{idx}:")
        for k, v in value.items():
            if isinstance(v, list):
                for i, e in enumerate(v):
                    _print_decoded_entry(e, idx=f"[{i}]")
            else:
                _print_decoded_entry(v)
    elif enum_name:
        print(f"  {label}{type_info}{idx} = {value} ({enum_name}) [{wt}]")
    else:
        print(f"  {label}{type_info}{idx} = {value} [{wt}]")


def cmd_validate(args):
    """Validate a protobuf binary against a .proto schema."""
    proto_file = parse_proto_file(args.proto)
    msg = proto_file.find_message(args.message_type)

    if not msg:
        print(f"Error: message type '{args.message_type}' not found in {args.proto}", file=sys.stderr)
        sys.exit(1)

    with open(args.file, "rb") as f:
        data = f.read()

    schema_fields: Dict[int, ProtoField] = {}
    for f in msg.fields:
        schema_fields[f.number] = f

    issues = []
    seen_fields = set()

    offset = 0
    while offset < len(data):
        tag, tag_consumed = read_varint(data, offset)
        if tag_consumed == 0:
            break
        offset += tag_consumed
        field_number = tag >> 3
        wire_type = tag & 0x07

        if field_number not in schema_fields:
            issues.append(f"Unknown field {field_number} (wire type {wire_type})")

        schema_field = schema_fields.get(field_number)
        if schema_field:
            expected_wire = SCALAR_TYPES.get(schema_field.type_name)
            if expected_wire is not None and expected_wire != wire_type:
                issues.append(
                    f"Field {field_number} ({schema_field.name}): "
                    f"expected wire type {expected_wire} ({WIRE_TYPE_NAMES.get(expected_wire, '?')}), "
                    f"got {wire_type} ({WIRE_TYPE_NAMES.get(wire_type, '?')})"
                )
            seen_fields.add(field_number)

        # Skip the field value
        if wire_type == WIRE_VARINT:
            _, consumed = read_varint(data, offset)
            offset += consumed
        elif wire_type == WIRE_64BIT:
            offset += 8
        elif wire_type == WIRE_LENGTH_DELIMITED:
            length, len_consumed = read_varint(data, offset)
            offset += len_consumed + length
        elif wire_type == WIRE_32BIT:
            offset += 4
        else:
            break

    # Check required fields
    for fn, f in schema_fields.items():
        if f.label == LABEL_REQUIRED and fn not in seen_fields:
            issues.append(f"Missing required field {fn} ({f.name})")

    result = {
        "valid": len(issues) == 0,
        "message_type": args.message_type,
        "issues": issues,
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
        return

    if not issues:
        print(f"✓ Valid: {args.message_type} conforms to schema ({len(data)} bytes)")
    else:
        print(f"✗ Validation found {len(issues)} issue(s):")
        for issue in issues:
            print(f"  - {issue}")


def cmd_raw(args):
    """Hex dump with field boundary detection."""
    with open(args.file, "rb") as f:
        data = f.read()

    if args.format == "json":
        fields = _raw_parse(data)
        print(json.dumps(fields, indent=2))
        return

    print(f"Raw inspection of {args.file} ({len(data)} bytes)")
    print()

    offset = 0
    field_idx = 0
    lines: List[str] = []

    while offset < len(data):
        if offset >= len(data):
            break
        tag, tag_consumed = read_varint(data, offset)
        if tag_consumed == 0:
            break
        field_number = tag >> 3
        wire_type = tag & 0x07
        wt_name = WIRE_TYPE_NAMES.get(wire_type, f"unknown({wire_type})")

        field_idx += 1
        tag_bytes = data[offset : offset + tag_consumed]
        tag_hex = tag_bytes.hex(" ")

        start_offset = offset
        offset += tag_consumed

        if wire_type == WIRE_VARINT:
            val, vc = read_varint(data, offset)
            val_bytes = data[offset : offset + vc]
            val_hex = val_bytes.hex(" ")
            offset += vc
            lines.append(
                f"  [{field_idx}] offset={start_offset:#06x} ({start_offset:>5}) "
                f"field={field_number}  wire={wt_name:<20} "
                f"tag={tag_hex:<8}  value_bytes={val_hex:<12} → {val}"
            )
        elif wire_type == WIRE_64BIT:
            val_bytes = data[offset : offset + 8]
            val_hex = val_bytes.hex(" ")
            offset += 8
            lines.append(
                f"  [{field_idx}] offset={start_offset:#06x} ({start_offset:>5}) "
                f"field={field_number}  wire={wt_name:<20} "
                f"tag={tag_hex:<8}  value_bytes={val_hex}"
            )
        elif wire_type == WIRE_LENGTH_DELIMITED:
            length, len_consumed = read_varint(data, offset)
            len_bytes = data[offset : offset + len_consumed]
            val_bytes = data[offset + len_consumed : offset + len_consumed + length]
            offset += len_consumed + length
            preview = ""
            try:
                decoded = val_bytes.decode("utf-8")
                if len(decoded) <= 60:
                    preview = f' → "{decoded}"'
                else:
                    preview = f' → "{decoded[:57]}..."'
            except UnicodeDecodeError:
                if length <= 16:
                    preview = f" → {val_bytes.hex(' ')}"
                else:
                    preview = f" → {val_bytes[:16].hex(' ')}..."
            lines.append(
                f"  [{field_idx}] offset={start_offset:#06x} ({start_offset:>5}) "
                f"field={field_number}  wire={wt_name:<20} "
                f"tag={tag_hex:<8}  len={length}{preview}"
            )
        elif wire_type == WIRE_32BIT:
            val_bytes = data[offset : offset + 4]
            val_hex = val_bytes.hex(" ")
            offset += 4
            lines.append(
                f"  [{field_idx}] offset={start_offset:#06x} ({start_offset:>5}) "
                f"field={field_number}  wire={wt_name:<20} "
                f"tag={tag_hex:<8}  value_bytes={val_hex}"
            )
        else:
            # Unknown wire type — advance one byte at a time
            lines.append(
                f"  [{field_idx}] offset={start_offset:#06x} ({start_offset:>5}) "
                f"field={field_number}  wire={wt_name:<20} "
                f"tag={tag_hex:<8}  [unknown wire type — stopping]"
            )
            break

    for line in lines:
        print(line)


def _raw_parse(data: bytes) -> List[Dict[str, Any]]:
    """Parse raw protobuf fields for JSON output."""
    fields = []
    offset = 0
    while offset < len(data):
        tag, tag_consumed = read_varint(data, offset)
        if tag_consumed == 0:
            break
        field_number = tag >> 3
        wire_type = tag & 0x07
        wt_name = WIRE_TYPE_NAMES.get(wire_type, f"unknown({wire_type})")
        start_offset = offset
        offset += tag_consumed

        entry: Dict[str, Any] = {
            "offset": start_offset,
            "field_number": field_number,
            "wire_type": wt_name,
        }

        if wire_type == WIRE_VARINT:
            val, vc = read_varint(data, offset)
            entry["value"] = val
            entry["size"] = tag_consumed + vc
            offset += vc
        elif wire_type == WIRE_64BIT:
            entry["value_hex"] = data[offset : offset + 8].hex()
            entry["size"] = tag_consumed + 8
            offset += 8
        elif wire_type == WIRE_LENGTH_DELIMITED:
            length, len_consumed = read_varint(data, offset)
            raw_val = data[offset + len_consumed : offset + len_consumed + length]
            offset += len_consumed + length
            entry["length"] = length
            try:
                entry["value"] = raw_val.decode("utf-8")
            except UnicodeDecodeError:
                entry["value_hex"] = raw_val.hex()
            entry["size"] = tag_consumed + len_consumed + length
        elif wire_type == WIRE_32BIT:
            entry["value_hex"] = data[offset : offset + 4].hex()
            entry["size"] = tag_consumed + 4
            offset += 4
        else:
            entry["size"] = tag_consumed
            break

        fields.append(entry)

    return fields


# ──────────────────────────────────────────────
#  Argument Parser
# ──────────────────────────────────────────────


def add_format_arg(subparser):
    subparser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proto_peek",
        description="Proto_Peek — Protocol Buffer inspector. "
        "Parse .proto files, decode raw protobuf, inspect field values. Zero deps.",
    )
    parser.add_argument("--version", action="version", version=f"Proto_Peek {__version__}")
    sub = parser.add_subparsers(dest="command", help="Subcommands")

    # parse
    p_parse = sub.add_parser("parse", help="Parse a .proto file and print its structure")
    p_parse.add_argument("file", help="Path to .proto file")
    add_format_arg(p_parse)

    # decode
    p_decode = sub.add_parser("decode", help="Decode a protobuf binary message")
    p_decode.add_argument("file", help="Path to .bin file")
    p_decode.add_argument("message_type", help="Message type name to decode as")
    p_decode.add_argument("--proto", help="Path to .proto schema file")
    add_format_arg(p_decode)

    # fields
    p_fields = sub.add_parser("fields", help="List fields of a message type")
    p_fields.add_argument("file", help="Path to .proto file")
    p_fields.add_argument("message_type", help="Message type name")
    add_format_arg(p_fields)

    # validate
    p_validate = sub.add_parser("validate", help="Validate binary against .proto schema")
    p_validate.add_argument("file", help="Path to .bin file")
    p_validate.add_argument("proto", help="Path to .proto schema file")
    p_validate.add_argument("message_type", help="Message type name")
    add_format_arg(p_validate)

    # raw
    p_raw = sub.add_parser("raw", help="Hex dump with field boundary detection")
    p_raw.add_argument("file", help="Path to .bin file")
    add_format_arg(p_raw)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "parse":
        cmd_parse(args)
    elif args.command == "decode":
        cmd_decode(args)
    elif args.command == "fields":
        cmd_fields(args)
    elif args.command == "validate":
        cmd_validate(args)
    elif args.command == "raw":
        cmd_raw(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
