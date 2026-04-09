# common.py

from pathlib import Path


def read_file_bytes(filename: str) -> bytes:
    return Path(filename).read_bytes()


def write_file_bytes(filename: str, data: bytes) -> None:
    Path(filename).write_bytes(data)


def bytes_to_bits(data: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in data)


def bits_to_bytes(bits: str) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("Количество бит должно быть кратно 8")
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def int_to_bits(value: int, width: int) -> str:
    if value < 0 or value >= (1 << width):
        raise ValueError(f"Число {value} не помещается в {width} бит")
    return format(value, f"0{width}b")


def bits_to_int(bits: str) -> int:
    if not bits:
        return 0
    return int(bits, 2)


def build_secret_bitstream(data: bytes, length_field_bits: int) -> str:
    payload_bits = bytes_to_bits(data)
    length_bits = int_to_bits(len(data), length_field_bits)
    return length_bits + payload_bits


def utf8_preview(data: bytes, max_bytes: int = 64) -> str:
    return data[:max_bytes].decode("utf-8", errors="replace")
