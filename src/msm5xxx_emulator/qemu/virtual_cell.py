"""Software scenario for an explicit ideal decoded network; default is off."""
import calendar
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
_GPS_LEAP_SECONDS = 18                 # GPS - UTC since 2017-01-01


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


def host_sync_message_hex(now: float | None = None) -> str:
    """Sync message carrying the host clock as CDMA system time and local offset."""
    now = time.time() if now is None else now
    local = time.localtime(now)
    gps_seconds = now - _GPS_EPOCH + _GPS_LEAP_SECONDS
    # LTM_OFF is in 30-minute units and already includes daylight saving.
    return sync_message_hex(int(gps_seconds / 0.08), _GPS_LEAP_SECONDS,
                            round(local.tm_gmtoff / 1800), 1 if local.tm_isdst > 0 else 0)


def virtual_cell_scenario(enabled: bool = False, *, now: float | None = None) -> dict | None:
    """Return fresh parameters; existing firmware signatures decide support."""
    if type(enabled) is not bool:
        raise TypeError("enabled must be a bool")
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
        'sync_message_hex': host_sync_message_hex(now),
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
