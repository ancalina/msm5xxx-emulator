"""Software scenario for an explicit ideal decoded network; default is off."""
import calendar
import math
import numbers
import time

_PAGING_MESSAGES = (
    '2101000022bbfffc00000000408000000000000000002aa800001c811032d5858d',
    '130200000000000000000000000880150f5501',
    '09030000202ddb8355',
    '09040000077f201358',
)

# Sync Channel Message template (P_REV 3): SYS_TIME 0, LC_STATE 1, LP_SEC/LTM_OFF/DAYLT 0.
_SYNC_TEMPLATE = '1a010303115dfffe00000000000040000000000000076374e349'
_SYNC_BITS = 26 * 8
# (first bit, width) of the time fields in the template above, MSB first.
_LC_STATE, _SYS_TIME, _LP_SEC, _LTM_OFF, _DAYLT = (72, 42), (114, 36), (150, 8), (158, 6), (164, 1)
_LONG_CODE_POLY = 0x40A8E6F04EF        # x^42 + x^35 + ... + x + 1 (IS-95 long code)
_CHIPS_PER_SYS_TIME = 98304            # 80 ms at 1.2288 Mcps
_GPS_EPOCH = calendar.timegm((1980, 1, 6, 0, 0, 0))
# GPS - UTC offset changes (UTC instant, seconds); later leap seconds must be appended here.
_LEAP_SECONDS = tuple((calendar.timegm((year, month, 1, 0, 0, 0)), offset) for year, month, offset in (
    (1981, 7, 1), (1982, 7, 2), (1983, 7, 3), (1985, 7, 4), (1988, 1, 5), (1990, 1, 6),
    (1991, 1, 7), (1992, 7, 8), (1993, 7, 9), (1994, 7, 10), (1996, 1, 11), (1997, 7, 12),
    (1999, 1, 13), (2006, 1, 14), (2009, 1, 15), (2012, 7, 16), (2015, 7, 17), (2017, 1, 18)))
# Deterministic default network time: 2002-11-21 09:05 local, broadcast with LTM_OFF +9 h.
# 1972년 11월 21일
DEFAULT_NETWORK_TIME = calendar.timegm((2002, 11, 21, 0, 5, 0))
DEFAULT_LTM_OFF = 18                   # +9 h in 30-minute units


def _crc30(value: int, bits: int) -> int:
    crc = 0x3fffffff
    for bit in range(bits - 1, -1, -1):
        feedback = ((crc >> 29) ^ (value >> bit)) & 1
        crc = ((crc << 1) ^ (0x6030b9c7 if feedback else 0)) & 0x3fffffff
    return (~crc) & 0x3fffffff


def _long_code_state(steps: int) -> int:
    """Long code state reached from state 1 after `steps` chips: x^steps mod p(x)."""
    def mulmod(a: int, b: int) -> int:
        product = 0
        while b:
            if b & 1:
                product ^= a
            b >>= 1
            a <<= 1
            if a >> 42:
                a ^= _LONG_CODE_POLY
        return product
    result, base = 1, 2
    while steps:
        if steps & 1:
            result = mulmod(result, base)
        base = mulmod(base, base)
        steps >>= 1
    return result


def sync_message_hex(sys_time: int, lp_sec: int = 0, ltm_off: int = 0, daylt: int = 0) -> str:
    """Sync Channel Message with SYS_TIME (80 ms units) and the matching LC_STATE."""
    if not (0 <= sys_time < 1 << 36 and 0 <= lp_sec < 256 and -32 <= ltm_off < 32
            and daylt in (0, 1)):
        raise ValueError("invalid sync message time fields")
    value = int(_SYNC_TEMPLATE, 16)
    for (first, width), field in ((_LC_STATE, _long_code_state(sys_time * _CHIPS_PER_SYS_TIME)),
                                  (_SYS_TIME, sys_time), (_LP_SEC, lp_sec),
                                  (_LTM_OFF, ltm_off & 0x3f), (_DAYLT, daylt)):
        shift = _SYNC_BITS - first - width
        value = (value & ~(((1 << width) - 1) << shift)) | (field << shift)
    prefix = value >> 30
    return ((prefix << 30) | _crc30(prefix, _SYNC_BITS - 30)).to_bytes(26, 'big').hex()


def _leap_seconds(utc: float) -> int:
    offset = 0
    for start, value in _LEAP_SECONDS:
        if utc >= start:
            offset = value
    return offset


def network_sync_message_hex(utc: float, ltm_off: int, daylt: int = 0) -> str:
    """Sync message announcing `utc` (POSIX seconds) as CDMA system time."""
    leap = _leap_seconds(utc)
    return sync_message_hex(int((utc - _GPS_EPOCH + leap) / 0.08), leap, ltm_off, daylt)


def host_sync_message_hex(now: float | None = None) -> str:
    """Sync message carrying the host clock, local offset and daylight flag."""
    now = time.time() if now is None else now
    local = time.localtime(now)
    # LTM_OFF is in 30-minute units and already includes daylight saving.
    return network_sync_message_hex(now, round(local.tm_gmtoff / 1800), 1 if local.tm_isdst > 0 else 0)


def virtual_cell_scenario(enabled: bool = False, *, host_time: bool = False,
                          now: float | None = None, start_time: float | None = None) -> dict | None:
    """Return fresh parameters; existing firmware signatures decide support.

    The announced network time is a fixed default so guest behaviour stays deterministic;
    host_time=True announces the host clock instead (`now` overrides it for tests).
    """
    if type(enabled) is not bool:
        raise TypeError("enabled must be a bool")
    if start_time is not None:
        if isinstance(start_time, bool) or not isinstance(start_time, numbers.Real):
            raise TypeError("start_time must be a number")
        if (not math.isfinite(start_time) or start_time < _GPS_EPOCH
                or (start_time - _GPS_EPOCH + _leap_seconds(start_time)) / 0.08 >= 1 << 36):
            raise ValueError("start_time outside CDMA system time range")
    if not enabled:
        return None
    # Ideal decoded input has no RF, SIP or successful-call guarantee.
    # shortcut: ideal decoded payload; replace after signaling and voice calibration.
    return {
        'allow_receive_only': True,
        'pilot_phase': 130088,
        'raw_energy': 64000,
        'virtual_delay_ns': 1000000,
        'decoder_init_delay_ns': 80000000,
        'sync_message_hex': (host_sync_message_hex(start_time) if start_time is not None else
                             host_sync_message_hex(now) if host_time else
                             network_sync_message_hex(DEFAULT_NETWORK_TIME, DEFAULT_LTM_OFF)),
        'paging_messages_hex': list(_PAGING_MESSAGES),
        'sid': 2222,
        'nid': 65535,
        'channel': 29,
        'tx_init_delay_ns': 1000000,
        'tx_frame_period_ns': 20000000,
        'access_response_probe': True,
        'access_assignment_code': 1,
        'traffic_decoder_probe': True,
        'traffic_frame_hex': 'auto',
    }
