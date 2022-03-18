import os
import sys
import json
import time
import argparse
import threading
import functools
from functools import partial


from logger import logger as log
from message import *
from netlink import Netlink
from ipc_socket import IPCSocket
from spine_flow import Flow, active_flowmap, send_port_map, flow_id_map
from poller import Action, Poller, ReturnStatus, PollEvents

# communication between spine-user-space and kernel
nl_sock = None
# communication between spine-user-space and Env
unix_sock = None
# cont status of polling
cont = threading.Event()

# unix socket message type
NEW = 0
CLOSE = 1


def build_unix_sock(unix_file):
    sock = IPCSocket()
    sock.connect(unix_file)
    sock.set_noblocking()
    return sock


def build_netlink_sock():
    sock = Netlink()
    sock.add_mc_group()
    return sock


def read_netlink_message(nl_sock: Netlink):
    hdr_raw = nl_sock.next_msg()
    if hdr_raw == None:
        return ReturnStatus.Cancel
    hdr = SpineMsgHeader()
    if hdr.from_raw(hdr_raw) == None:
        log.error("Failed to parse netlink header")
        return ReturnStatus.Cancel
    if hdr.type == CREATE:
        msg = CreateMsg()
        msg.from_raw(hdr_raw[hdr.hdr_len :])
        flow = Flow().from_create_msg(msg, hdr)
        # register new flow
        if not flow.sock_id in active_flowmap:
            active_flowmap[flow.sock_id] = flow
            log.info("new kernel flow: {}".format(flow.sock_id))
            # try to associate sock id with flow id
            if msg.src_port in send_port_map:
                # first look up flow id from send port
                flow_id = send_port_map[msg.src_port]
                if flow_id not in flow_id_map:
                    flow_id_map[flow_id] = flow.sock_id
                    log.info(
                        "associate env flow id: {} with kernel sock id: {}".format(
                            flow_id, flow.sock_id
                        )
                    )
        else:
            log.warn("duplicate flow: {}".format(hdr.sock_id))
        return ReturnStatus.Continue
    elif hdr.type == READY:
        log.info("Spine kernel is ready!!")
    elif hdr.type == MEASURE:
        sock_id = hdr.sock_id
        if sock_id in active_flowmap:
            log.info("remove kernel flow: {}".format(sock_id))# 
            # i am responsible for these two maps
            send_port_map.pop(active_flowmap[sock_id].src_port)
            active_flowmap.pop(sock_id)
    return ReturnStatus.Continue



def read_unix_message(unix_sock: IPCSocket):
    raw = unix_sock.read(header=True)
    if raw == None:
        return ReturnStatus.Cancel
    data = json.load(raw)
    flow_id = data["flow_id"]
    msg_type = data["type"]
    # associate spine-kernel sock id with flow_id
    if msg_type == NEW:
        send_port = data["send_port"]
        if not send_port in send_port_map:
            send_port_map[send_port] = flow_id
            # no need to process other information
            return ReturnStatus.Continue
    elif msg_type == CLOSE:
        if send_port in send_port_map:
            flow_id_map.pop(flow_id)
            return ReturnStatus.Continue

    # do we know the sock id?
    if not flow_id in flow_id_map:
        log.warn("Unknown flow id: {}".format(flow_id))
        return ReturnStatus.Continue
    # we have all the info we need
    # specific for cubic
    if "cubic_beta" in data and "cubic_bic_scale" in data:
        cubic_beta = int(data["cubic_data"])
        cubic_bic_scale = int(data["cubic_bic_scale"])
    msg = UpdateMsg()
    msg.add_field(
        UpdateField().create(VOLATILE_CONTROL_REG, CUBIC_BETA_REG, cubic_beta)
    )
    msg.add_field(
        UpdateField().create(VOLATILE_CONTROL_REG, CUBIC_BIC_SCALE_REG, cubic_bic_scale)
    )
    update_msg = msg.serialize()
    nl_hdr = SpineMsgHeader()
    if flow_id in flow_id_map:
        sock_id = flow_id_map[flow_id]
    else:
        log.warn("unknown flow id: {}".format(flow_id))
        return ReturnStatus.Continue
    nl_hdr.create(CREATE, len(update_msg) + nl_hdr.hdr_len, sock_id)
    nl_sock.send_msg(nl_hdr.serialize() + update_msg)
    return ReturnStatus.Continue


def polling(poller: Poller):
    while not cont.is_set():
        if poller.poll_once() == False:
            time.sleep(0.1)


def main(args):
    poller = Poller()
    # unix_sock: recv updated parameters and relay to nl_sock
    unix_read_wrapper = partial(read_unix_message, unix_sock)
    poller.add_action(
        Action(unix_sock, PollEvents.READ_ERR_FLAGS, callback=unix_read_wrapper)
    )
    # recv new spine flow info and misc
    netlink_read_wrapper = partial(read_netlink_message, nl_sock)
    poller.add_action(
        Action(nl_sock, PollEvents.READ_ERR_FLAGS, callback=netlink_read_wrapper)
    )
    threading.Thread(target=polling, args=(poller)).run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ipc",
        "-i",
        type=str,
        required=True,
        help="IPC communication between Env and Spine controller",
    )
    args = parser.parse_args()
    # build communication sockets
    unix_sock = build_unix_sock(args.ipc)
    nl_sock = build_netlink_sock()

    main(args)
