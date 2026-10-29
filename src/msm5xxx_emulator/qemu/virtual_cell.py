"""Software scenario for an explicit ideal decoded network; default is off."""

_PAGING_MESSAGES = (
    '2101000022bbfffc00000000408000000000000000002aa800001c811032d5858d',
    '130200000000000000000000000880150f5501',
    '09030000202ddb8355',
    '09040000077f201358',
)


def virtual_cell_scenario(enabled: bool = False) -> dict | None:
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
        'sync_message_hex': '1a010303115dfffe00000000000040000000000000076374e349',
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
