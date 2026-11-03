"""Instruction signatures for small-page NAND drivers."""

import hashlib
import struct

RAW_NAND_LOW_PORT_RESET_SIGNATURE = bytes.fromhex("ff200521490508707047")
RAW_NAND_LOW_PORT_STATUS_SIGNATURE = bytes.fromhex(
    "00200121c9050522520580b4702717700b78c02b08d0c12b03d0044b01309842"
    "f5d3022080bc70470120fbe7"
)
RAW_NAND_LOW_PORT_READ_SIGNATURE = bytes.fromhex(
    "f0b5010a07063f0e00220c06240e50250026fff7e7ff05204005057009210905"
    "0e70381c104308700c70fff7e0ff0120c0050088064b984203d0"
)
RAW_NAND_LOW_PORT_ERASE_SIGNATURE = bytes.fromhex(
    "80b5010a0f063f0e0206120efff778ff60200521490508700920000502700770"
    "d0200870fff771fffff752"
)
RAW_NAND_LOW_PORT_PROGRAM_SIGNATURE = bytes.fromhex(
    "05204005ff2301339a4201d2002100e05021017080210170092202991205117015"
    "7001991170e107c90f0125ed05002907d103e04a00a25a2a800131b142f9d30ce0"
    "002108e06218167800ab1e7056785e701a882a800231b942f4d310210170"
)


def find_low_port_nand_driver(image: bytes) -> bool:
    return all(signature in image for signature in (
        RAW_NAND_LOW_PORT_RESET_SIGNATURE, RAW_NAND_LOW_PORT_STATUS_SIGNATURE,
        RAW_NAND_LOW_PORT_READ_SIGNATURE, RAW_NAND_LOW_PORT_ERASE_SIGNATURE,
        RAW_NAND_LOW_PORT_PROGRAM_SIGNATURE))


def find_middle_nand_driver_marker(image: bytes) -> bool:
    """Recognize the embedded driver marker and its three bus apertures."""
    return (b"fs_ks_nand.c" in image.lower()
            and all(struct.pack('<I', port) in image
                    for port in (0x01800000, 0x01900000, 0x01a00000)))


_SINGLE_RESET_READY = tuple(map(bytes.fromhex, (
    '0348406801888909fcd37047',
    '0348406801884909fcd37047',
    '90b405480021054a01271770117043681c88a308f9d3',
    '90b405480021054a01271770117043691c88a309f9d3',
    '80b5044ff7f717f9786900888009f9d380bc08bc1847',
)))
_AMBIGUOUS_READY = tuple(map(bytes.fromhex, (
    '0348406a0188090bfcd37047', '0348406a0188c908fcd37047',
)))
_KNOWN_DRIVER_BODY = 'd465facb8125b6621b22f30990e2925201434630453112ae51a606df0eae3ccd'


def find_middle_nand_producers(image: bytes) -> bool:
    """Recognize reset and command/address/data producers for the middle bus."""
    reset = bytes.fromhex('ff200d21490508707047')
    operations = (bytes.fromhex('0d204005'), bytes.fromhex('19210905'),
                  bytes.fromhex('0320c005'))
    ports = (0x01800000, 0x01900000, 0x01a00000)
    resets = []
    at = 0
    while (at := image.find(reset, at)) >= 0:
        if not at & 1:
            resets.append(at)
        at += 2
    commands = (bytes.fromhex('0d204005'), bytes.fromhex('70200d235b05'),
                bytes.fromhex('0d225205'))
    if (not resets or not all(struct.pack('<I', port) in image for port in ports)
            or not any(code in image for code in commands)
            or bytes.fromhex('0320c005') not in image):
        return False
    unambiguous = [at for at in resets if not any(
        image.startswith(shape, at + len(reset)) for shape in _AMBIGUOUS_READY)]
    known_body = any(hashlib.sha256(image[at:at + 64]).hexdigest() == _KNOWN_DRIVER_BODY
                     for at in resets if at <= len(image) - 64)
    common = len(unambiguous) >= 2 and all(code in image for code in operations)
    ready = any(any(image.startswith(shape, at + len(reset))
                    for shape in _SINGLE_RESET_READY) for at in unambiguous)
    return common or ready or known_body
