import argparse
import os
import queue
import random
import socket
import time

from constants import (
    DEFAULT_BIND_HOST,
    DEFAULT_P1_PORT,
    PACKET_SIZE,
    BASE_INTERVAL_MIN,
    BASE_INTERVAL_MAX,
    DELTA,
    INITIAL_LEVEL,
    LENGTH_FIELD_BITS,
)
from common import read_file_bytes, build_secret_bitstream


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Covert channel emulation: variant 2 (Model 2 + Example 10)',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        '-f', '--filename',
        help='data to transfer via covert channel',
        required=True,
        dest='filename',
        type=str
    )
    parser.add_argument(
        '--host',
        help='receiver host/IP',
        required=False,
        dest='host',
        type=str,
        default=DEFAULT_BIND_HOST
    )
    parser.add_argument(
        '--port',
        help='receiver UDP port',
        required=False,
        dest='port',
        type=int,
        default=DEFAULT_P1_PORT
    )
    parser.add_argument(
        '--seed',
        help='random seed for reproducible experiments',
        required=False,
        dest='seed',
        type=int,
        default=None
    )

    return parser.parse_args()


def build_legitimate_packet(seq: int) -> bytes:
    """
    Формирует пакет фиксированной длины.
    Содержимое - легитимные данные, скрытая информация в payload не кладется.
    """
    header = f"LEGIT:{seq:08d}|".encode("ascii")
    if len(header) > PACKET_SIZE:
        raise ValueError("PACKET_SIZE слишком мал для заголовка")
    padding = os.urandom(PACKET_SIZE - len(header))
    return header + padding


def sleep_precisely(seconds: float):
    if seconds > 0:
        time.sleep(seconds)


def send_with_buffering(sock: socket.socket, addr: tuple[str, int], packet: bytes, interval: float):
    """
    Эмуляция буферизации:
    1. Пакет кладется в буфер.
    2. Ждет нужное время.
    3. Уходит в сеть без изменения содержимого.
    """
    buf = queue.Queue()
    buf.put(packet)

    sleep_precisely(interval)

    data = buf.get()
    sock.sendto(data, addr)


def main():
    args = parse_arguments()

    secret_data = read_file_bytes(args.filename)
    bitstream = build_secret_bitstream(
        data=secret_data,
        length_field_bits=LENGTH_FIELD_BITS
    )

    rng = random.Random(args.seed)

    print(f"[INFO] secret file: {args.filename}")
    print(f"[INFO] secret bytes: {len(secret_data)}")
    print(f"[INFO] total bits to send: {len(bitstream)}")
    print(f"[INFO] length field bits: {LENGTH_FIELD_BITS}")
    print(f"[INFO] payload bits: {len(secret_data) * 8}")
    print(f"[INFO] base interval range: [{BASE_INTERVAL_MIN:.3f}, {BASE_INTERVAL_MAX:.3f}] s")
    print(f"[INFO] delta: {DELTA:.3f} s")
    print(f"[INFO] initial level: {INITIAL_LEVEL}")

    addr = (args.host, args.port)
    current_level = INITIAL_LEVEL

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Стартовый синхропакет.
        # После него приемник начинает измерять интервалы.
        sync_packet = build_legitimate_packet(0)
        sock.sendto(sync_packet, addr)
        print("[SYNC] initial packet sent")

        seq = 1

        for idx, bit in enumerate(bitstream, start=1):
            base_interval = rng.uniform(BASE_INTERVAL_MIN, BASE_INTERVAL_MAX)

            if bit == "1":
                current_level = 1 - current_level

            actual_interval = base_interval + (DELTA if current_level == 1 else 0.0)

            packet = build_legitimate_packet(seq)
            send_with_buffering(sock, addr, packet, actual_interval)

            print(
                f"[SEND] bit#{idx:05d}={bit} "
                f"base={base_interval:.6f}s "
                f"level={current_level} "
                f"actual={actual_interval:.6f}s "
                f"seq={seq}"
            )

            seq += 1

    print("[INFO] transmission finished")


if __name__ == "__main__":
    main()
