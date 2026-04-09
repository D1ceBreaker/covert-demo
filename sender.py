"""
ПК1: модель 2 — в фоне кладёт пакеты в очередь со случайными короткими интервалами.

Закладка: паузы t / t+Δ по примеру 10, выдача из очереди.

Отдельного пакета seq=0 нет: первый пакет потока (seq=1) выходит из очереди
без паузы закладки и задаёт опору времени; первый бит преамбулы кодируется
интервалом до второго пакета. Далее — преамбула, длина, полезная нагрузка.
"""

import argparse
import os
import queue
import random
import socket
import threading
import time

from constants import (
    DEFAULT_BIND_HOST,
    DEFAULT_P1_PORT,
    PACKET_SIZE,
    PC1_INTERVAL_MIN,
    PC1_INTERVAL_MAX,
    IMPLANT_INTERVAL_T,
    DELTA,
    PREAMBLE_BITS,
    LENGTH_FIELD_BITS,
)
from common import read_file_bytes, build_secret_bitstream
from implant import CovertImplant


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="ПК1 (модель 2) + закладка (пример 10), очередь между ними",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-f",
        "--filename",
        help="файл для передачи по скрытому каналу",
        required=True,
        dest="filename",
        type=str,
    )
    parser.add_argument(
        "--host",
        help="хост/адрес приёмника или УЗ",
        required=False,
        dest="host",
        type=str,
        default=DEFAULT_BIND_HOST,
    )
    parser.add_argument(
        "--port",
        help="UDP-порт",
        required=False,
        dest="port",
        type=int,
        default=DEFAULT_P1_PORT,
    )
    parser.add_argument(
        "--seed",
        help="seed ГПСЧ для ПК1 (случайные интервалы генерации в буфер)",
        required=False,
        dest="seed",
        type=int,
        default=None,
    )

    return parser.parse_args()


class LegitimatePacketSource:
    """Пакеты фиксированного размера; скрытый груз только в очереди на отправку закладкой."""

    def build_packet(self, seq: int) -> bytes:
        header = f"LEGIT:{seq:08d}|".encode("ascii")
        if len(header) > PACKET_SIZE:
            raise ValueError("PACKET_SIZE слишком мал для заголовка")
        padding = os.urandom(PACKET_SIZE - len(header))
        return header + padding


def pc1_producer_loop(
    pc1: LegitimatePacketSource,
    packet_queue: queue.Queue[bytes],
    rng: random.Random,
    stop_event: threading.Event,
    first_seq: int,
) -> None:
    """ПК1: кладёт пакеты в очередь с случайными короткими интервалами."""
    seq = first_seq
    while not stop_event.is_set():
        pkt = pc1.build_packet(seq)
        seq += 1
        packet_queue.put(pkt)
        delay = rng.uniform(PC1_INTERVAL_MIN, PC1_INTERVAL_MAX)
        if stop_event.wait(delay):
            break


def main():
    args = parse_arguments()

    secret_data = read_file_bytes(args.filename)
    bitstream = build_secret_bitstream(
        data=secret_data,
        preamble_bits=PREAMBLE_BITS,
        length_field_bits=LENGTH_FIELD_BITS,
    )

    rng_pc1 = random.Random(args.seed)
    pc1 = LegitimatePacketSource()
    implant = CovertImplant()

    packet_queue: queue.Queue[bytes] = queue.Queue()
    stop_event = threading.Event()

    print(f"[INFO] ПК1: в буфер пакеты — случайно каждые "
          f"[{PC1_INTERVAL_MIN:.3f}, {PC1_INTERVAL_MAX:.3f}] с (быстрее выдачи t и t+Δ)")
    print(f"[INFO] закладка: паузы только t={IMPLANT_INTERVAL_T:.3f} с или t+Δ={IMPLANT_INTERVAL_T + DELTA:.3f} с (без разброса)")
    print(f"[INFO] файл: {args.filename}, байт: {len(secret_data)}")
    print(f"[INFO] преамбула: {len(PREAMBLE_BITS)} бит, поле длины: {LENGTH_FIELD_BITS}, бит к передаче: {len(bitstream)}")

    addr = (args.host, args.port)

    producer = threading.Thread(
        target=pc1_producer_loop,
        args=(pc1, packet_queue, rng_pc1, stop_event, 1),
        daemon=True,
    )

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        producer.start()
        deadline = time.monotonic() + 5.0
        while packet_queue.qsize() < 1 and time.monotonic() < deadline:
            time.sleep(0.001)
        if packet_queue.qsize() < 1:
            stop_event.set()
            producer.join(timeout=1.0)
            raise RuntimeError("ПК1 не успел положить первый пакет (seq=1) в очередь")

        # Якорь: первый пакет без паузы закладки; первый бит потока — интервал до следующего пакета
        implant.wait_and_send_from_queue(sock, addr, packet_queue, 0.0)
        print("[START] якорь: первый пакет (seq=1) из очереди, без паузы закладки")

        for idx, bit in enumerate(bitstream, start=1):
            base_interval, actual_interval = implant.intervals_for_bit(bit)
            implant.wait_and_send_from_queue(sock, addr, packet_queue, actual_interval)

            print(
                f"[SEND] bit#{idx:05d}={bit} "
                f"base={base_interval:.6f}s "
                f"level={implant.current_level} "
                f"actual={actual_interval:.6f}s "
                f"queue≈{packet_queue.qsize()}"
            )

        stop_event.set()
        producer.join(timeout=2.0)

    print("[INFO] передача завершена")


if __name__ == "__main__":
    main()
