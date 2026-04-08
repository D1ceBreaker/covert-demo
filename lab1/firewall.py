# protection_device.py

import argparse
import socket
import time

from constants import (
    DEFAULT_BIND_HOST,
    DEFAULT_P2_HOST,
    DEFAULT_UZ_LISTEN_PORT,
    DEFAULT_P2_LISTEN_PORT,
    SOCKET_TIMEOUT_SECONDS,
    RECV_BUFFER_SIZE,
)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Protection device in passive mode: receive and forward traffic unchanged',
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

    return parser.parse_args()


def main():
    args = parse_arguments()

    print(f"[INFO] protection device started")
    print(f"[INFO] listen on: {args.bind_host}:{args.listen_port}")
    print(f"[INFO] forward to: {args.forward_host}:{args.forward_port}")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as recv_sock, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as send_sock:

        recv_sock.bind((args.bind_host, args.listen_port))
        recv_sock.settimeout(SOCKET_TIMEOUT_SECONDS)

        packet_count = 0
        byte_count = 0

        while True:
            try:
                data, src_addr = recv_sock.recvfrom(RECV_BUFFER_SIZE)
            except socket.timeout:
                print("[INFO] timeout waiting for packets, protection device still running")
                continue
            except KeyboardInterrupt:
                print("\n[INFO] protection device stopped by user")
                break

            timestamp = time.monotonic()

            # Пассивный режим: пакет не модифицируется
            send_sock.sendto(data, (args.forward_host, args.forward_port))

            packet_count += 1
            byte_count += len(data)

            print(
                f"[FORWARD] time={timestamp:.6f} "
                f"from={src_addr} "
                f"to=({args.forward_host}, {args.forward_port}) "
                f"size={len(data)} "
                f"packets={packet_count} "
                f"bytes={byte_count}"
            )


if __name__ == "__main__":
    main()
