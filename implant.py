"""
Закладка внутри ПК1: забирает уже сгенерированные легитимные пакеты из очереди
и отправляет их в сеть в детерминированные моменты по примеру 10 (без ГПСЧ).
Случайность остаётся только на стороне штатной генерации ПК1.
"""

from __future__ import annotations

import queue
import socket
import time

from constants import DELTA, IMPLANT_INTERVAL_T, INITIAL_LEVEL


class CovertImplant:
    """
    Задаёт только «правильные» интервалы между отправками: базовая величина фиксирована,
    бит «1» переключает уровень; к базе при уровне 1 добавляется дельта.
    Пакеты не создаёт — получает из очереди, наполняемой ПК1.
    """

    def __init__(self):
        self._current_level = INITIAL_LEVEL

    @property
    def current_level(self) -> int:
        return self._current_level

    def reset_level(self) -> None:
        self._current_level = INITIAL_LEVEL

    def intervals_for_bit(self, bit: str) -> tuple[float, float]:
        """
        Базовый интервал — t; при уровне 1 фактический t + Δ (без разброса).
        Возвращает (base_interval, actual_interval до следующей отправки).
        """
        base = IMPLANT_INTERVAL_T
        if bit == "1":
            self._current_level = 1 - self._current_level
        actual = base + (DELTA if self._current_level == 1 else 0.0)
        return base, actual

    def wait_and_send_from_queue(
        self,
        sock: socket.socket,
        addr: tuple[str, int],
        packet_queue: queue.Queue[bytes],
        delay_seconds: float,
        get_timeout: float = 60.0,
    ) -> None:
        """
        Выдерживает интервал по расписанию закладки, затем забирает следующий пакет
        из буфера ПК1 и отправляет его.
        """
        if delay_seconds > 0:
            time.sleep(delay_seconds)
        packet = packet_queue.get(timeout=get_timeout)
        sock.sendto(packet, addr)
