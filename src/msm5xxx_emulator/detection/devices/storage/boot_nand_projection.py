"""Serialize an admitted NAND bootstrap plan without querying firmware."""
from dataclasses import dataclass
from msm5xxx_emulator.detection.capabilities import ResourceClaim


@dataclass(frozen=True)
class BootNandBinding:
    cpu: str
    machine: str
    raw_size: int
    main_size: int
    high_code_size: int


def _word_properties(parameters):
    if set(parameters) != {'identity_status', 'peripherals', 'control_windows',
                          'lcd_data_port', 'lcd_identity'}:
        raise ValueError('invalid word NAND peripheral parameters')
    identity = parameters['identity_status']
    peripherals = parameters['peripherals']
    windows = parameters['control_windows']
    data_port = parameters['lcd_data_port']
    lcd_identity = parameters['lcd_identity']
    if (type(identity) is not int or not 0 < identity <= 0x7fffffff
            or identity & 0x7fff or type(peripherals) is not int
            or peripherals < 0 or peripherals > 7
            or type(data_port) is not int
            or (data_port not in (0x20040000, 0x20080000) if peripherals & 1 else data_port != 0)
            or type(lcd_identity) is not int or lcd_identity not in (0, 0x7068)
            or lcd_identity and not peripherals & 1
            or not isinstance(windows, tuple) or len(windows) > 16):
        raise ValueError('invalid word NAND peripheral contract')
    previous_end = 0
    for window in windows:
        if (not isinstance(window, tuple) or len(window) != 2
                or any(type(value) is not int for value in window)):
            raise ValueError('invalid word NAND control window')
        start, end = window
        if (start <= 0 or start < previous_end or not start < end <= 0x100000000
                or end - start > 0x100000 or (start | end) & 0xfff):
            raise ValueError('invalid word NAND control bounds')
        previous_end = end
    properties = (('bootstrap-nand-word-interface', 1),
                  ('bootstrap-nand-id-status', identity),
                  ('bootstrap-nand-word-peripherals', peripherals))
    if peripherals & 1:
        properties += (('bootstrap-nand-lcd-data-port', data_port),)
        if lcd_identity:
            properties += (('bootstrap-nand-lcd-id', lcd_identity),)
    if windows:
        value = ':'.join(f'{value:x}' for start, end in windows
                         for value in (start, end - start))
        properties += (('bootstrap-nand-control-windows', value),)
    return properties


def word_claims(windows, peripherals, data_port=0):
    """Describe the exact regions realized by the word controller adapter."""
    ports = (0x20000000, data_port)
    ranges = [(0, 0x04000000), (0xffff0000, 0x100000000),
              (0x64000000, 0x64001000), (0x80000000, 0x80010000), *windows]
    if peripherals & 1:
        ranges.extend(((ports[0], ports[0] + 8), (ports[1], ports[1] + 32)))
    if peripherals & 4 and not any(start <= 0x48000050 and 0x48000054 <= end
                                    for start, end in ranges):
        ranges.append((0x48000050, 0x48000054))
    return tuple(ResourceClaim('address', 'high-linked-nand-bootstrap', start, end,
        shared_resource='indexed28-stream' if peripherals & 1 and start in ports else None,
        semantics='native-write-observer' if peripherals & 1 and start in ports else None)
        for start, end in ranges)


def project(plan):
    choices = [capability for capability in plan.capabilities
               if capability.name == 'high-linked-nand-bootstrap']
    if not choices:
        return None
    if len(choices) != 1:
        raise ValueError('ambiguous NAND bootstrap plan')
    parameters = dict(choices[0].parameters)
    word = parameters.pop('word_interface', False)
    extra = {key: parameters.pop(key) for key in
             ('identity_status', 'peripherals', 'control_windows',
              'lcd_data_port', 'lcd_identity') if key in parameters}
    if (set(parameters) != {'cpu', 'raw_size', 'main_size', 'high_code_size'}
            or type(word) is not bool or not word and extra):
        raise ValueError('invalid NAND bootstrap parameters')
    cpu = parameters['cpu']
    raw, main, high = (parameters[key] for key in ('raw_size', 'main_size', 'high_code_size'))
    properties = (('bootstrap-nand-main-size', main),) + (
        _word_properties(extra) if word else ())
    if (cpu != 'arm926,reset-hivecs=on'
            or word and main not in (0x04000000, 0x08000000)
            or any(type(value) is not int for value in (raw, main, high))
            or not 0 < main <= 0x08000000 or main % 16384
            or raw != main + main // 32 or high != 0x2000
            or tuple(sorted(choices[0].properties)) != tuple(sorted(properties))
            or word and getattr(choices[0], 'claims', None) != word_claims(
                extra['control_windows'], extra['peripherals'], extra['lcd_data_port'])):
        raise ValueError('unsupported NAND bootstrap contract')
    machine = ''.join(f',{name}={value}' for name, value in properties)
    return BootNandBinding(cpu, machine, raw, main, high)
