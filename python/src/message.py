import os
import sys
import struct

from logger import logger as log

# message types
CREATE = 0
MEASURE = 1
INSTALL_EXPR = 2
UPDATE_FIELDS = 3
CHANGE_PROG = 4
READY = 5
# spine message types
STATE = 6
PARAM = 7
NEURAL_NETWORK = 8

# type of registers
VOLATILE_CONTROL_REG = 8

# registers for Cubic Parameters
CUBIC_BETA_REG = 0
CUBIC_BIC_SCALE_REG = 1

# some length of message
SPINE_HEADER_LEN = 8
SPINE_CREATE_LEN = 88


class SpineMsgHeader(object):
    def __init__(self):
        self.hdr_len = 2 + 2 + 4
        self.raw_format = "=HHI"
        self.type = -1
        self.len = -1
        self.sockId = -1

    def from_raw(self, buf):
        if not isinstance(buf, bytes):
            log.error("expected bytes")
            return False
        if len(buf) < self.hdr_len:
            log.error("header length too small")
            return False
        self.type, self.len, self.sockId = struct.unpack(self.raw_format, buf[0:8])
        # do some sanity check
        if not (self.sockId > 0):
            log.error("incorrect socket id")
            return False
        return True
    
    def create(self, type, len, sock):
        self.type = type
        self.len = len
        self.sock = sock

    def serialize(self):
        return struct.pack(self.raw_format, self.type, self.len, self.sockId)


class CreateMsg(object):
    def __init__(self):
        self.msg_len = 4 * 6 + 64
        self.int_raw_format = "=IIIIII"
        self.int_len = struct.calcsize(self.int_raw_format)

        self.init_cwnd = 0
        self.mss = 0
        self.src_ip = 0
        self.src_port = 0
        self.dst_ip = 0
        self.dst_port = 0
        # max 64 bytes
        self.congAlg = ""

    def from_raw(self, buf):
        # first process message
        if len(buf) < self.msg_len:
            log.error("message length too small")
        (
            self.init_cwnd,
            self.mss,
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
        ) = struct.unpack(buf[: self.int_len])
        # remaining part is char array
        self.congAlg = buf[self.int_len :].decode()


class UpdateField(object):
    def __init__(self):
        self.field_len = 1 + 4 + 8
        self.raw_format = "=BIQ"

        self.reg_type = -1
        self.reg_index = -1
        self.new_value = -1

    def create(self, type, index, value):
        self.reg_type = type
        self.reg_index = index
        self.new_value = value

    def serialize(self):
        return struct.pack(
            self.raw_format, self.reg_type, self.reg_index, self.new_vale
        )
    
    def deserialize(self, buf):
        if len(buf) < self.field_len:
            log.error("message length too small")
        self.reg_type, self.reg_index, self.new_value = struct.unpack(
            self.raw_format, buf[: self.field_len]
        )


class UpdateMsg(object):
    def __init__(self):
        self.num_fields = 0
        self.fields = []

    def add_field(self, field):
        self.fields.append(field)
        self.num_fields += 1

    def serialize(self):
        buf = struct.pack("=I", self.num_fields)
        for field in self.fields:
            buf += field.serialize()
        return buf

    def deserialize(self, buf):
        self.num_fields = struct.unpack("=I", buf[0:4])
        for i in range(self.num_fields):
            field = UpdateField()
            field.deserialize(buf[4 + i * field.field_len :])
            self.fields.append(field)


def ReadyMsg(object):
    def __init__(self):
        self.msg_len = 4
        # u32 
        self.ready = 0
    
    def serialize(self):
        return struct.pack("=I", self.ready)
    
    def deserialize(self, buf):
        self.ready = struct.unpack("=I", buf[0:4])