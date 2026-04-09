import argparse
import os
import queue
import random
import socket
import threading
import time

from constants import (
    DEFAULT_BIND_HOST,
    DEFAULT_P2_HOST,
    DEFAULT_UZ_LISTEN_PORT,
    DEFAULT_P2_LISTEN_PORT,
    SOCKET_TIMEOUT_SECONDS,
    RECV_BUFFER_SIZE,
    DUMMY_PACKET_SIZE,
    DEFENSE_NONE,
    DEFENSE_LIMIT,
    DEFENSE_NORMALIZE,
    LIMIT_DUMMY_PROBABILITY,
    LIMIT_DUMMY_DELAY_MIN,
    LIMIT_DUMMY_DELAY_MAX,
    NORMALIZE_INTERVAL,
)

PROTECTED_PREFIX_REAL_FORWARDS = 1


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.received_packets = 0
        self.received_bytes = 0
        self.forwarded_real_packets = 0
        self.forwarded_real_bytes = 0
        self.injected_dummy_packets = 0
        self.injected_dummy_bytes = 0

    def add_received(self, size: int):
        with self.lock:
            self.received_packets += 1
            self.received_bytes += size

    def add_real_forwarded(self, size: int):
        with self.lock:
            self.forwarded_real_packets += 1
            self.forwarded_real_bytes += size

    def add_dummy_forwarded(self, size: int):
        with self.lock:
            self.injected_dummy_packets += 1
            self.injected_dummy_bytes += size

    def snapshot(self):
        with self.lock:
            return {
                "received_packets": self.received_packets,
                "received_bytes": self.received_bytes,
                "forwarded_real_packets": self.forwarded_real_packets,
                "forwarded_real_bytes": self.forwarded_real_bytes,
                "injected_dummy_packets": self.injected_dummy_packets,
                "injected_dummy_bytes": self.injected_dummy_bytes,
            }


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Protection device with optional covert-channel countermeasures',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        '--bind-host',
        help='address to bind protection device',
        required=False,
        dest='bind_host',
        type=str,
        default=DEFAULT_BIND_HOST
    )
    parser.add_argument(
        '--listen-port',
        help='UDP port where protection device receives traffic from sender',
        required=False,
        dest='listen_port',
        type=int,
        default=DEFAULT_UZ_LISTEN_PORT
    )
    parser.add_argument(
        '--forward-host',
        help='receiver host/IP where traffic is forwarded',
        required=False,
        dest='forward_host',
        type=str,
        default=DEFAULT_P2_HOST
    )
    parser.add_argument(
        '--forward-port',
        help='receiver UDP port where traffic is forwarded',
        required=False,
        dest='forward_port',
        type=int,
        default=DEFAULT_P2_LISTEN_PORT
    )

    parser.add_argument(
        '--defense',
        help='defense mode',
        required=False,
        dest='defense',
        type=str,
        choices=[DEFENSE_NONE, DEFENSE_LIMIT, DEFENSE_NORMALIZE],
        default=DEFENSE_NONE
    )

    return parser.parse_args()


def build_dummy_packet(size: int) -> bytes:
    return os.urandom(size)


def send_packet(send_sock: socket.socket, send_lock: threading.Lock, data: bytes, dest_addr):
    with send_lock:
        send_sock.sendto(data, dest_addr)


def print_stats(stats: Stats, prefix: str = "[STATS]"):
    snap = stats.snapshot()
    print(
        f"{prefix} "
        f"received_packets={snap['received_packets']} "
        f"received_bytes={snap['received_bytes']} "
        f"forwarded_real_packets={snap['forwarded_real_packets']} "
        f"forwarded_real_bytes={snap['forwarded_real_bytes']} "
        f"injected_dummy_packets={snap['injected_dummy_packets']} "
        f"injected_dummy_bytes={snap['injected_dummy_bytes']}"
    )


def delayed_dummy_sender(send_sock, send_lock, dest_addr, delay, dummy_size, stats: Stats, stop_event: threading.Event):
    if stop_event.wait(delay):
        return

    dummy_packet = build_dummy_packet(dummy_size)
    send_packet(send_sock, send_lock, dummy_packet, dest_addr)
    stats.add_dummy_forwarded(len(dummy_packet))

    print(
        f"[LIMIT][DUMMY] delay={delay:.6f}s "
        f"to={dest_addr} "
        f"size={len(dummy_packet)}"
    )


def run_no_defense(recv_sock, send_sock, send_lock, dest_addr, stats: Stats):
    print("[INFO] defense mode: none")

    while True:
        try:
            data, src_addr = recv_sock.recvfrom(RECV_BUFFER_SIZE)
        except socket.timeout:
            continue

        timestamp = time.monotonic()
        stats.add_received(len(data))

        send_packet(send_sock, send_lock, data, dest_addr)
        stats.add_real_forwarded(len(data))

        print(
            f"[FORWARD][NONE] time={timestamp:.6f} "
            f"from={src_addr} "
            f"to={dest_addr} "
            f"size={len(data)}"
        )


def run_limit_defense(recv_sock, send_sock, send_lock, dest_addr, stats: Stats):
    print("[INFO] defense mode: limit")
    print(f"[INFO] dummy probability (after SYNC): {LIMIT_DUMMY_PROBABILITY}")
    print(f"[INFO] no dummy after forwarding first {PROTECTED_PREFIX_REAL_FORWARDS} real packet(s) (SYNC)")
    print(f"[INFO] dummy delay range: [{LIMIT_DUMMY_DELAY_MIN}, {LIMIT_DUMMY_DELAY_MAX}] s")
    print(f"[INFO] dummy size: {DUMMY_PACKET_SIZE}")

    rng = random.Random(None)
    stop_event = threading.Event()
    dummy_threads = []

    try:
        while True:
            try:
                data, src_addr = recv_sock.recvfrom(RECV_BUFFER_SIZE)
            except socket.timeout:
                continue

            timestamp = time.monotonic()
            stats.add_received(len(data))

            send_packet(send_sock, send_lock, data, dest_addr)
            stats.add_real_forwarded(len(data))

            print(
                f"[FORWARD][LIMIT][REAL] time={timestamp:.6f} "
                f"from={src_addr} "
                f"to={dest_addr} "
                f"size={len(data)}"
            )

            if stats.forwarded_real_packets <= PROTECTED_PREFIX_REAL_FORWARDS:
                continue

            if rng.random() < LIMIT_DUMMY_PROBABILITY:
                delay = rng.uniform(LIMIT_DUMMY_DELAY_MIN, LIMIT_DUMMY_DELAY_MAX)

                th = threading.Thread(
                    target=delayed_dummy_sender,
                    args=(send_sock, send_lock, dest_addr, delay, DUMMY_PACKET_SIZE, stats, stop_event),
                    daemon=True
                )
                th.start()
                dummy_threads.append(th)

    except KeyboardInterrupt:
        print("\n[INFO] stopping protection device (limit mode)")
    finally:
        stop_event.set()
        for th in dummy_threads:
            th.join(timeout=0.2)


def normalize_input_worker(recv_sock, packet_queue: queue.Queue, stop_event: threading.Event, first_packet_event: threading.Event, stats: Stats):
    while not stop_event.is_set():
        try:
            data, src_addr = recv_sock.recvfrom(RECV_BUFFER_SIZE)
        except socket.timeout:
            continue

        stats.add_received(len(data))
        packet_queue.put(data)

        if not first_packet_event.is_set():
            first_packet_event.set()

        print(
            f"[NORMALIZE][IN] from={src_addr} "
            f"size={len(data)} "
            f"queue_size={packet_queue.qsize()}"
        )


def sleep_until(target_time: float, stop_event: threading.Event):
    while not stop_event.is_set():
        remaining = target_time - time.monotonic()
        if remaining <= 0:
            return
        stop_event.wait(min(remaining, 0.05))


def dequeue_real_blocking(packet_queue: queue.Queue, stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            return packet_queue.get(timeout=0.1)
        except queue.Empty:
            pass
    return None


def normalize_output_worker(send_sock, send_lock, dest_addr, packet_queue: queue.Queue, stop_event: threading.Event,
                            first_packet_event: threading.Event, stats: Stats, normalize_interval: float, dummy_size: int):
    print("[NORMALIZE][OUT] waiting for first packet")

    # Ждем первый пакет, чтобы не слать пустой поток до начала сеанса
    while not stop_event.is_set():
        if first_packet_event.wait(timeout=0.1):
            break

    if stop_event.is_set():
        return

    try:
        first_packet = packet_queue.get(timeout=1.0)
    except queue.Empty:
        return

    send_packet(send_sock, send_lock, first_packet, dest_addr)
    stats.add_real_forwarded(len(first_packet))
    print(
        f"[NORMALIZE][OUT][REAL-FIRST] to={dest_addr} "
        f"size={len(first_packet)}"
    )

    next_send_time = time.monotonic() + normalize_interval

    while not stop_event.is_set():
        sleep_until(next_send_time, stop_event)
        if stop_event.is_set():
            break

        try:
            packet = packet_queue.get_nowait()
            send_packet(send_sock, send_lock, packet, dest_addr)
            stats.add_real_forwarded(len(packet))

            print(
                f"[NORMALIZE][OUT][REAL] to={dest_addr} "
                f"size={len(packet)} "
                f"queue_size={packet_queue.qsize()}"
            )
        except queue.Empty:
            if stats.forwarded_real_packets < PROTECTED_PREFIX_REAL_FORWARDS + 1:
                packet = dequeue_real_blocking(packet_queue, stop_event)
                if packet is None:
                    return
                send_packet(send_sock, send_lock, packet, dest_addr)
                stats.add_real_forwarded(len(packet))
                print(
                    f"[NORMALIZE][OUT][REAL] to={dest_addr} "
                    f"size={len(packet)} "
                    f"queue_size={packet_queue.qsize()} (after SYNC, no dummy)"
                )
            else:
                dummy_packet = build_dummy_packet(dummy_size)
                send_packet(send_sock, send_lock, dummy_packet, dest_addr)
                stats.add_dummy_forwarded(len(dummy_packet))

                print(
                    f"[NORMALIZE][OUT][DUMMY] to={dest_addr} "
                    f"size={len(dummy_packet)}"
                )

        next_send_time += normalize_interval


def run_normalize_defense(recv_sock, send_sock, send_lock, dest_addr, stats: Stats):
    print("[INFO] defense mode: normalize")
    print(f"[INFO] normalize interval: {NORMALIZE_INTERVAL}")
    print(f"[INFO] no dummies on empty queue until {PROTECTED_PREFIX_REAL_FORWARDS + 1} real packets (SYNC + first data)")
    print(f"[INFO] dummy size: {DUMMY_PACKET_SIZE}")

    stop_event = threading.Event()
    first_packet_event = threading.Event()
    packet_queue = queue.Queue()

    input_thread = threading.Thread(
        target=normalize_input_worker,
        args=(recv_sock, packet_queue, stop_event, first_packet_event, stats),
        daemon=True
    )

    output_thread = threading.Thread(
        target=normalize_output_worker,
        args=(send_sock, send_lock, dest_addr, packet_queue, stop_event, first_packet_event, stats,
              NORMALIZE_INTERVAL, DUMMY_PACKET_SIZE),
        daemon=True
    )

    input_thread.start()
    output_thread.start()

    try:
        while True:
            time.sleep(1.0)
            print_stats(stats, prefix="[NORMALIZE][STATS]")
    except KeyboardInterrupt:
        print("\n[INFO] stopping protection device (normalize mode)")
    finally:
        stop_event.set()
        input_thread.join(timeout=1.0)
        output_thread.join(timeout=1.0)


def main():
    args = parse_arguments()

    dest_addr = (args.forward_host, args.forward_port)
    stats = Stats()
    send_lock = threading.Lock()

    print("[INFO] protection device started")
    print(f"[INFO] listen on: {args.bind_host}:{args.listen_port}")
    print(f"[INFO] forward to: {args.forward_host}:{args.forward_port}")
    print(f"[INFO] defense: {args.defense}")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as recv_sock, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as send_sock:

        recv_sock.bind((args.bind_host, args.listen_port))
        recv_sock.settimeout(SOCKET_TIMEOUT_SECONDS)

        try:
            if args.defense == DEFENSE_NONE:
                run_no_defense(recv_sock, send_sock, send_lock, dest_addr, stats)
            elif args.defense == DEFENSE_LIMIT:
                run_limit_defense(recv_sock, send_sock, send_lock, dest_addr, stats)
            elif args.defense == DEFENSE_NORMALIZE:
                run_normalize_defense(recv_sock, send_sock, send_lock, dest_addr, stats)
            else:
                raise ValueError(f"Unknown defense mode: {args.defense}")
        except KeyboardInterrupt:
            print("\n[INFO] protection device stopped by user")
        finally:
            print_stats(stats)


if __name__ == "__main__":
    main()
