import os
import sys

from message import *

active_flowmap = dict()


class Flow(object):
    def __init__(self):
        self.sk_id = -1
        self.init_cwnd = 0
        self.mss = 0
        self.src_ip = 0
        self.src_port = 0
        self.dst_ip = 0
        self.dst_port = 0
        # max 64 bytes
        self.congAlg = ""

    def from_cr(self, msg: CreateMsg, hdr: SpineMsgHeader):
        self.init_cwnd = msg.init_cwnd
        self.mss = msg.mss
        self.src_ip = msg.src_ip
        self.src_port = msg.src_port
        self.dst_ip = msg.dst_ip
        self.dst_port = msg.dst_port
        # max 64 bytes
        self.congAlg = msg.congAlg

        # key in flow map
        self.sk_id = hdr.sockId