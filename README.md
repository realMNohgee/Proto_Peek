# Proto_Peek
![CI](https://github.com/realMNohgee/Proto_Peek/actions/workflows/ci.yml/badge.svg) ![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg) ![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Protocol Buffer inspector. Parse .proto files, decode raw protobuf, inspect field values. Zero deps.**

[![Hermtica Marketplace](https://img.shields.io/badge/Hermtica-Marketplace-blue)](https://hermtica.com/marketplace/proto-peek)

---

## Features

- **`parse`** — Parse `.proto` files and print messages, enums, services with full field details
- **`decode`** — Decode raw protobuf binary using an optional `.proto` schema for typed output
- **`fields`** — List all fields of a message type: name, number, type, label
- **`validate`** — Check binary data conforms to a `.proto` schema
- **`raw`** — Hex dump with intelligent field boundary detection (varint / length-delimited guesses)

All subcommands support `--format text|json`.

## Requirements

- Python 3.7+
- **Zero dependencies** — pure Python stdlib

## Installation

```bash
# Clone
git clone git@github.com:realMNohgee/Proto_Peek.git
cd Proto_Peek

# Run directly
python3 proto_peek.py --help

# Or make it executable
chmod +x proto_peek.py
./proto_peek.py --help
```

## Usage

### Parse a .proto file

```bash
python3 proto_peek.py parse example.proto
python3 proto_peek.py parse example.proto --format json
```

Output:
```
Syntax: proto3
Package: example

── Messages (2) ──

  message Person {
    string name = 1;
    int32 age = 2;
    repeated string tags = 3;
  }
```

### Decode a protobuf binary

```bash
python3 proto_peek.py decode data.bin Person --proto example.proto
python3 proto_peek.py decode data.bin Person --proto example.proto --format json
```

Output:
```
Decoded 'Person' (42 bytes):
  name (string) = "Alice"
  age (int32) = 30
  tags[0] (string) = "dev"
  tags[1] (string) = "gamer"
```

### List message fields

```bash
python3 proto_peek.py fields example.proto Person
python3 proto_peek.py fields example.proto Person --format json
```

### Validate binary against schema

```bash
python3 proto_peek.py validate data.bin example.proto Person
```

### Raw hex dump with field detection

```bash
python3 proto_peek.py raw data.bin
python3 proto_peek.py raw data.bin --format json
```

## Supported Types

| Proto Type  | Wire Type         | Decoding            |
|-------------|-------------------|---------------------|
| int32/64    | varint            | raw varint          |
| uint32/64   | varint            | raw varint          |
| sint32/64   | varint            | zigzag-decoded      |
| bool        | varint            | true/false          |
| enum        | varint            | resolved name       |
| fixed32     | 32-bit            | little-endian u32   |
| fixed64     | 64-bit            | little-endian u64   |
| sfixed32    | 32-bit            | little-endian i32   |
| sfixed64    | 64-bit            | little-endian i64   |
| float       | 32-bit            | IEEE 754            |
| double      | 64-bit            | IEEE 754            |
| string      | length-delimited  | UTF-8               |
| bytes       | length-delimited  | hex                 |
| message     | length-delimited  | nested decode       |

## License

MIT — see [LICENSE](./LICENSE)

## Links

- [Hermtica Marketplace](https://hermtica.com/marketplace/proto-peek)
- [Protocol Buffers Documentation](https://protobuf.dev/)
