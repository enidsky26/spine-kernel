import os
from socket import socket
import sys

from message import *


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


class ActiveFlowMap(object):
    def __init__(self):
        # key is sock id (assigned by spine-kernel)
        self.flowmap = dict()
        # key is flow id (assigned by Env), value is sock id
        self.flow_id_map = dict()
        # key is dst_port, value is flow id
        self.dst_port_map = dict()

    def try_associate(self, flow: Flow):
        if flow.dst_port in self.dst_port_map:
            # first look up flow id from send port
            flow_id = self.dst_port_map[flow.dst_port]
            if flow_id not in self.flow_id_map:
                self.flow_id_map[flow_id] = flow.sock_id
                log.info(
                    "associate env flow id: {} with kernel sock id: {}".format(
                        flow_id, flow.sock_id
                    )
                )

    def add_flow_with_sockId(self, flow: Flow):
        if flow.sock_id not in self.flowmap:
            self.flowmap[flow.sock_id] = flow
            log.info(
                "add kernel flow: {} with init_cwnd: {},src_ip: {}, src_port: {}, dst_ip: {}, dst_port: {}".format(
                    flow.sock_id,
                    flow.init_cwnd,
                    ipaddress.IPv4Address(flow.src_ip),
                    flow.src_port,
                    ipaddress.IPv4Address(flow.dst_ip),
                    flow.dst_port,
                )
            )
            self.try_associate(flow)
            return True
        else:
            log.warn("flow already exists: {}".format(flow.sock_id))
            return False

    def add_flow_with_dst_port(self, port, flow_id):
        if not port in self.dst_port_map:
            self.dst_port_map[port] = flow_id
            log.info("register env flow: {} with dst_port: {}".format(flow_id, port))

    def get_sockId_by_flowId(self, flow_id):
        if flow_id in self.flow_id_map:
            return self.flow_id_map[flow_id]
        else:
            return None

    def remove_flow_by_sockId(self, sock_id):
        if sock_id in self.flowmap:
            # they should exists in these two maps
            port = self.flowmap[sock_id].dst_port
            if port in self.dst_port_map:
                self.dst_port_map.pop(port)
            log.info("remove kernel flow: {}".format(sock_id))
            self.flowmap.pop(sock_id)
            return True
        log.warn("unknown kernel flow {}".format(sock_id))
        return False

    def remove_flow_by_flowId(self, flow_id):
        if flow_id in self.flow_id_map:
            self.flow_id_map.pop(flow_id)
            return True
        # leave other stuff to callback of netlink release mesage
        return False

    def remove_all_env_flows(self):
        for flow_id in self.flow_id_map.copy():
            self.flow_id_map.pop(flow_id)


class EnvFlows(object):
    def __init__(self):
        self.env_id = None
        # hash of env id
        self.h_id = None
        self.flows_per_env = dict()

    def register_env(self, env_id):
        self.env_id = env_id
        self.h_id = hash(self.env_id)
        self.flows_per_env[self.h_id] = ActiveFlowMap()

    def get_env_flows(self, env_id):
        id = hash(env_id)
        if id in self.flows_per_env:
            return self.flows_per_env[id]
        else:
            return None

    def release_env(self, env_id):
        id = hash(env_id)
        if id in self.flows_per_env:
            self.flows_per_env.pop(id)
