import struct
from functools import partial

U8 = 0xFF
U32 = 0xFFFFFFFF

# fmt: off
TEST_PROG = [
    0x50, 0x48, 0xC2, 0x02, 0xA8, 0x4D, 0x00, 0x00, 0x00, 0x4F, 0x02, 0x50,
    0x09, 0xC4, 0x02, 0x02, 0xE1, 0x01, 0x4F, 0x02, 0xC1, 0x22, 0x1D, 0x00,
    0x00, 0x00, 0x48, 0x30, 0x02, 0x58, 0x03, 0x4F, 0x02, 0xB0, 0x29, 0x00,
    0x00, 0x00, 0x48, 0x31, 0x02, 0x50, 0x0C, 0xC3, 0x02, 0xAA, 0x57, 0x48,
    0x02, 0xC1, 0x21, 0x3A, 0x00, 0x00, 0x00, 0x48, 0x32, 0x02, 0x48, 0x77,
    0x02, 0x48, 0x6F, 0x02, 0x48, 0x72, 0x02, 0x48, 0x6C, 0x02, 0x48, 0x64,
    0x02, 0x48, 0x21, 0x02, 0x01, 0x65, 0x6F, 0x33, 0x34, 0x2C,
]
# fmt: on


def get_u8(obj, attr):
    return getattr(obj, attr) & U8


def set_u8(obj, value, attr):
    setattr(obj, attr, value & U8)


def get_u32(obj, attr):
    return getattr(obj, attr) & U32


def set_u32(obj, value, attr):
    setattr(obj, attr, value & U32)


class Tomtel:
    a = property(partial(get_u8, attr="_a"), partial(set_u8, attr="_a"))
    b = property(partial(get_u8, attr="_b"), partial(set_u8, attr="_b"))
    c = property(partial(get_u8, attr="_c"), partial(set_u8, attr="_c"))
    d = property(partial(get_u8, attr="_d"), partial(set_u8, attr="_d"))
    e = property(partial(get_u8, attr="_e"), partial(set_u8, attr="_e"))
    f = property(partial(get_u8, attr="_f"), partial(set_u8, attr="_f"))
    la = property(partial(get_u32, attr="_la"), partial(set_u32, attr="_la"))
    lb = property(partial(get_u32, attr="_lb"), partial(set_u32, attr="_lb"))
    lc = property(partial(get_u32, attr="_lc"), partial(set_u32, attr="_lc"))
    ld = property(partial(get_u32, attr="_ld"), partial(set_u32, attr="_ld"))
    ptr = property(partial(get_u32, attr="_ptr"), partial(set_u32, attr="_ptr"))
    pc = property(partial(get_u32, attr="_pc"), partial(set_u32, attr="_pc"))

    @property
    def ptr_c(self):
        return self.memory[(self.ptr + self.c) & U32]

    @ptr_c.setter
    def ptr_c(self, value):
        self.memory[(self.ptr + self.c) & U32] = value & U8

    def __init__(self):
        self.OPS = {
            0x01: (1, self._halt),
            0x02: (1, self._out),
            0xC1: (1, self._cmp),
            0xC2: (1, self._add),
            0xC3: (1, self._sub),
            0xC4: (1, self._xor),
            0xE1: (2, self._aptr),
            0x21: (5, self._jez),
            0x22: (5, self._jnz),
        }
        self.U8_REG = {
            1: "a",
            2: "b",
            3: "c",
            4: "d",
            5: "e",
            6: "f",
            7: "ptr_c",
        }
        self.U32_REG = {
            1: "la",
            2: "lb",
            3: "lc",
            4: "ld",
            5: "ptr",
            6: "pc",
        }
        self.reset()

    def reset(self, memory=None):
        self._a = 0  # accumulator
        self._b = 0  # operand
        self._c = 0  # count/offset
        self._d = 0  # general
        self._e = 0  # general
        self._f = 0  # flags
        self._la = 0  # general
        self._lb = 0  # general
        self._lc = 0  # general
        self._ld = 0  # general
        self._ptr = 0  # pointer
        self._pc = 0  # counter
        # ptr_c memory cursor _ptr + _c
        self.memory = memory if memory else []
        self.output = []

    def run(self, memory):
        self.reset(memory)
        while True:
            opcode = self.memory[self.pc]
            if opcode in self.OPS:
                size, op = self.OPS[opcode]
                self.pc += size
                if op():  # halt is the only instruction that returns true
                    break
            elif opcode >> 6 == 0b01 and opcode & 0b111:
                self.pc += 1
                self._mv()
            elif opcode >> 6 == 0b01:
                self.pc += 2
                self._mvi()
            elif opcode >> 6 == 0b10 and opcode & 0b111:
                self.pc += 1
                self._mv32()
            elif opcode >> 6 == 0b10:
                self.pc += 5
                self._mvi32()
            else:
                raise Exception(f"Unknown instruction: {opcode:02x}")
        return "".join(self.output)

    def _halt(self):
        """0x01"""
        return True

    def _out(self):
        """0x02"""
        self.output.append(chr(self.a))

    def _cmp(self):
        """0xC1"""
        self.f = 0 if self.a == self.b else 1

    def _add(self):
        """0xC2"""
        self.a += self.b

    def _sub(self):
        """0xC3"""
        self.a -= self.b

    def _xor(self):
        """0xC4"""
        self.a ^= self.b

    def _aptr(self):
        """0xE1 imm8"""
        self.ptr += self.memory[self.pc - 1]

    def _jez(self):
        """0x21 imm32"""
        v = struct.unpack("<L", bytes(self.memory[self.pc - 4 : self.pc]))[0]
        self.pc = v if self.f == 0 else self.pc

    def _jnz(self):
        """0x22 imm32"""
        v = struct.unpack("<L", bytes(self.memory[self.pc - 4 : self.pc]))[0]
        self.pc = v if self.f != 0 else self.pc

    def _mv(self):
        """
        0b01dddsss, d and s are 3 bit dest and source
        valid d|s values: 1-7 for a-ptr_c
        """
        s = self.memory[self.pc - 1] & 0b111
        d = (self.memory[self.pc - 1] >> 3) & 0b111
        setattr(self, self.U8_REG[d], getattr(self, self.U8_REG[s]))

    def _mvi(self):
        """
        0b01ddd000, d and s are 3 bit dest and source
        valid d|s values: 1-7 for a-ptr_c
        """
        v = self.memory[self.pc - 1]
        d = (self.memory[self.pc - 2] >> 3) & 0b111
        setattr(self, self.U8_REG[d], v)

    def _mv32(self):
        """
        0b10dddsss, d and s are 3 bit dest and source
        valid d|s values: 1-6 for la-pc
        """
        s = self.memory[self.pc - 1] & 0b111
        d = (self.memory[self.pc - 1] >> 3) & 0b111
        setattr(self, self.U32_REG[d], getattr(self, self.U32_REG[s]))

    def _mvi32(self):
        """
        0b10ddd000, d and s are 3 bit dest and source
        valid d|s values: 1-6 for la-pc
        """
        v = struct.unpack("<L", bytes(self.memory[self.pc - 4 : self.pc]))[0]
        d = (self.memory[self.pc - 5] >> 3) & 0b111
        setattr(self, self.U32_REG[d], v)
