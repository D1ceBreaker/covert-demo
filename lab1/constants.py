DEFAULT_BIND_HOST = "0.0.0.0"

DEFAULT_UZ_HOST = "127.0.0.1"
DEFAULT_P2_HOST = "127.0.0.1"

DEFAULT_UZ_LISTEN_PORT = 4000

DEFAULT_P2_LISTEN_PORT = 5000

DEFAULT_P1_PORT = 3000

PACKET_SIZE = 256

BASE_INTERVAL_MIN = 0.180
BASE_INTERVAL_MAX = 0.220

DELTA = 0.100

INITIAL_LEVEL = 0

LEVEL_THRESHOLD = (
    BASE_INTERVAL_MAX + (BASE_INTERVAL_MIN + DELTA)
) / 2.0

# Служебные параметры

LENGTH_FIELD_BITS = 32

SOCKET_TIMEOUT_SECONDS = 20.0
RECV_BUFFER_SIZE = 65535

TEXT_PREVIEW_BYTES = 64

# -------------------------------------------------
# Параметры защиты на устройстве защиты
# -------------------------------------------------

# Режимы:
# none       - защита отключена
# limit      - ограничение пропускной способности скрытого канала
# normalize  - полное устранение скрытого канала
DEFENSE_NONE = "none"
DEFENSE_LIMIT = "limit"
DEFENSE_NORMALIZE = "normalize"

# Для режима limit:
# вероятность вставки фиктивного пакета после каждого реального (после стартового SYNC)
LIMIT_DUMMY_PROBABILITY = 0.15

# задержка фиктивного пакета после реального
LIMIT_DUMMY_DELAY_MIN = 0.05
LIMIT_DUMMY_DELAY_MAX = 0.15

# Для режима normalize:
# фиксированный интервал выдачи пакетов на выходе УЗ
NORMALIZE_INTERVAL = 0.18

# Размер фиктивного пакета
DUMMY_PACKET_SIZE = PACKET_SIZE