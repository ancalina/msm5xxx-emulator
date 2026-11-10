"""Small declarative Thumb-1 instruction patterns for source admission."""
import struct

def mov(register, immediate):
    return 0x2000 | register << 8 | immediate

def cmp_imm(register, immediate):
    return 0x2800 | register << 8 | immediate

def lsl(destination, source, amount):
    return amount << 6 | source << 3 | destination

def halfword(load, target, base, offset=0):
    return (0x8800 if load else 0x8000) | (offset // 2) << 6 | base << 3 | target

def match(image, instructions):
    return all(0 <= at <= len(image) - 2 and struct.unpack_from('<H', image, at)[0] == word for at, word in instructions)
