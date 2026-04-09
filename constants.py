DEFAULT_BIND_HOST = "0.0.0.0"

DEFAULT_UZ_HOST = "127.0.0.1"
DEFAULT_P2_HOST = "127.0.0.1"

DEFAULT_UZ_LISTEN_PORT = 4000

DEFAULT_P2_LISTEN_PORT = 5000

DEFAULT_P1_PORT = 3000

PACKET_SIZE = 256

# ПК1: единственный разброс — случайный интервал между помещением пакетов в буфер
# (верхняя граница не выше t закладки, чтобы накопление в очереди опережало выдачу)
PC1_INTERVAL_MIN = 0.1
PC1_INTERVAL_MAX = 0.2

# Закладка: фиксированные задержки между отправками по примеру 10 — t или t + Δ, без разброса
IMPLANT_INTERVAL_T = 0.2
DELTA = 0.1

INITIAL_LEVEL = 0

# Порог между «коротким» (t) и «длинным» (t + Δ) интервалом на приёмнике
LEVEL_THRESHOLD = (IMPLANT_INTERVAL_T + IMPLANT_INTERVAL_T + DELTA) / 2.0

# Преамбула в битовом потоке (после служебного SYNC-пакета seq=0)
PREAMBLE_BITS = "10101010"

LENGTH_FIELD_BITS = 32

SOCKET_TIMEOUT_SECONDS = 20.0
RECV_BUFFER_SIZE = 65535

TEXT_PREVIEW_BYTES = 64

DEFENSE_NONE = "none"
DEFENSE_LIMIT = "limit"
DEFENSE_NORMALIZE = "normalize"

LIMIT_DUMMY_PROBABILITY = 0.15

LIMIT_DUMMY_DELAY_MIN = 0.05
LIMIT_DUMMY_DELAY_MAX = 0.15

NORMALIZE_INTERVAL = IMPLANT_INTERVAL_T

DUMMY_PACKET_SIZE = PACKET_SIZE
