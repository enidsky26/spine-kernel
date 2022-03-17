import os
import sys

from message import *

# key is sock id 
active_flowmap = dict()
# key is flow id, value is sock id
flow_id_map = dict()
# key is hash(send_port), value is flow id
send_port_map = dict()

class Flow(object):
    def __init__(self):
        self.sock_id = -1
        # flow info
        self.init_cwnd = 0
        self.mss = 0
        self.src_ip = 0
        self.src_port = 0
        self.dst_ip = 0
        self.dst_port = 0
        # max 64 bytes
        self.congAlg = ""

    def from_create_msg(self, msg: CreateMsg, hdr: SpineMsgHeader):
        self.init_cwnd = msg.init_cwnd
        self.mss = msg.mss
        self.src_ip = msg.src_ip
        self.src_port = msg.src_port
        self.dst_ip = msg.dst_ip
        self.dst_port = msg.dst_port
        # max 64 bytes
        self.congAlg = msg.congAlg

        # key in flow map
        self.sock_id = hdr.sock_id
        return self
