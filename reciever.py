import argparse
import socket
import time

from constants import (
    DEFAULT_BIND_HOST,
    DEFAULT_P2_LISTEN_PORT,
    INITIAL_LEVEL,
    LEVEL_THRESHOLD,
    PREAMBLE_BITS,
    LENGTH_FIELD_BITS,
    SOCKET_TIMEOUT_SECONDS,
    RECV_BUFFER_SIZE,
    TEXT_PREVIEW_BYTES,
)
from common import bits_to_bytes, bits_to_int, write_file_bytes, utf8_preview


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Covert channel receiver: variant 2 (Model 2 + Example 10)',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        '-o', '--output',
        help='output file for recovered covert data',
        required=True,
        dest='output',
        type=str
    )
    parser.add_argument(
        '--bind-host',
        help='bind address',
        required=False,
        dest='bind_host',
        type=str,
        default=DEFAULT_BIND_HOST
    )
    parser.add_argument(
        '--port',
        help='UDP port to listen on',
        required=False,
        dest='port',
        type=int,
        default=DEFAULT_P2_LISTEN_PORT
    )

    return parser.parse_args()


def recv_packet(sock: socket.socket):
    data, addr = sock.recvfrom(RECV_BUFFER_SIZE)
    timestamp = time.monotonic()
    return data, addr, timestamp


def classify_level(interval: float) -> int:
    return 0 if interval < LEVEL_THRESHOLD else 1


def decode_next_bit(sock: socket.socket, prev_timestamp: float, prev_level: int):
    data, addr, now = recv_packet(sock)
    interval = now - prev_timestamp
    current_level = classify_level(interval)

    bit = "0" if current_level == prev_level else "1"

    print(
        f"[RECV] from={addr} size={len(data)} "
        f"interval={interval:.6f}s "
        f"prev_level={prev_level} "
        f"curr_level={current_level} "
        f"bit={bit}"
    )

    return bit, now, current_level


def decode_n_bits(sock: socket.socket, prev_timestamp: float, prev_level: int, count: int, stage: str):
    bits = []

    for idx in range(1, count + 1):
        bit, prev_timestamp, prev_level = decode_next_bit(sock, prev_timestamp, prev_level)
        bits.append(bit)
        print(f"[{stage}] bit#{idx:05d}={bit}")

    return "".join(bits), prev_timestamp, prev_level


def main():
    args = parse_arguments()

    print(f"[INFO] PC2 listening on {args.bind_host}:{args.port}")
    print(f"[INFO] threshold: {LEVEL_THRESHOLD:.6f}s")
    print(f"[INFO] initial level: {INITIAL_LEVEL}")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((args.bind_host, args.port))
        sock.settimeout(SOCKET_TIMEOUT_SECONDS)

        data, addr, prev_timestamp = recv_packet(sock)
        prev_level = INITIAL_LEVEL

        print(f"[START] первый пакет (якорь) от {addr}, size={len(data)}")

        preamble_bits, prev_timestamp, prev_level = decode_n_bits(
            sock=sock,
            prev_timestamp=prev_timestamp,
            prev_level=prev_level,
            count=len(PREAMBLE_BITS),
            stage="PREAMBLE",
        )

        print(f"[INFO] ожидаемая преамбула: {PREAMBLE_BITS}")
        print(f"[INFO] принятая преамбула: {preamble_bits}")
        if preamble_bits != PREAMBLE_BITS:
            raise RuntimeError("Преамбула не совпала, декодирование прервано.")

        length_bits, prev_timestamp, prev_level = decode_n_bits(
            sock=sock,
            prev_timestamp=prev_timestamp,
            prev_level=prev_level,
            count=LENGTH_FIELD_BITS,
            stage="LENGTH",
        )

        payload_length_bytes = bits_to_int(length_bits)
        payload_bit_count = payload_length_bytes * 8

        print(f"[INFO] payload length: {payload_length_bytes} bytes")
        print(f"[INFO] payload bit count: {payload_bit_count}")

        payload_bits, prev_timestamp, prev_level = decode_n_bits(
            sock=sock,
            prev_timestamp=prev_timestamp,
            prev_level=prev_level,
            count=payload_bit_count,
            stage="PAYLOAD"
        )

        recovered_data = bits_to_bytes(payload_bits)
        write_file_bytes(args.output, recovered_data)

        print(f"[INFO] recovered file saved to: {args.output}")
        print(f"[INFO] recovered bytes: {len(recovered_data)}")
        print(f"[INFO] UTF-8 preview: {utf8_preview(recovered_data, TEXT_PREVIEW_BYTES)!r}")


if __name__ == "__main__":
    main()
