from enum import Enum
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
from spine_flow import Flow, ActiveFlowMap
from poller import Action, Poller, ReturnStatus, PollEvents

# communication between spine-user-space and kernel
nl_sock = None
# communication between spine-user-space and Env
unix_sock = None
# cont status of polling
cont = threading.Event()
active_flow_map = ActiveFlowMap()

class MessageType(Enum):
    INIT = 0  # env initialization
    START = 1  # episode start
    END = 2  # episode end
    ALIVE = 3  # alive status
    OBSERVE = 4  # observe the world


def build_unix_sock(unix_file):
    sock = IPCSocket()
    sock.bind(unix_file)
    sock.set_noblocking()
    sock.listen()
    log.info("Spine is listening for flows from env")
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
        active_flow_map.add_flow_with_sockId(flow)
        return ReturnStatus.Continue
    elif hdr.type == READY:
        log.info("Spine kernel is ready!!")
    elif hdr.type == MEASURE:
        sock_id = hdr.sock_id
        active_flow_map.remove_flow_by_sockId(sock_id)
    return ReturnStatus.Continue


def read_unix_message(unix_sock: IPCSocket):
    raw = unix_sock.read(header=True)
    if raw == None:
        return ReturnStatus.Cancel
    data = json.load(raw)
    flow_id = data["flow_id"]
    msg_type = data["type"]
    # associate spine-kernel sock id with flow_id
    if msg_type == MessageType.START.value:
        port = data["dst_port"]
        active_flow_map.add_flow_with_dst_port(port, flow_id)
        return ReturnStatus.Continue
    elif msg_type == MessageType.END.value:
        active_flow_map.remove_flow_by_flowId(flow_id)
        return ReturnStatus.Continue
    # message should be ALIVE
    if msg_type != MessageType.ALIVE.value:
        log.error("Incorrect message type: {}".format(msg_type))
        return ReturnStatus.Cancel
    # lookup sock id by flow_id
    sock_id = active_flow_map.lookup_flow_by_flowId(flow_id)
    if sock_id == None:
        log.warn("unknown flow id: {}".format(flow_id))
        return ReturnStatus.Continue
    
    if "cubic_beta" in data and "cubic_bic_scale" in data["action"]:
        cubic_beta = int(data["action"]["cubic_data"])
        cubic_bic_scale = int(data["action"]["cubic_bic_scale"])
    msg = UpdateMsg()
    msg.add_field(
        UpdateField().create(VOLATILE_CONTROL_REG, CUBIC_BETA_REG, cubic_beta)
    )
    msg.add_field(
        UpdateField().create(VOLATILE_CONTROL_REG, CUBIC_BIC_SCALE_REG, cubic_bic_scale)
    )
    update_msg = msg.serialize()
    nl_hdr = SpineMsgHeader()
    nl_hdr.create(CREATE, len(update_msg) + nl_hdr.hdr_len, sock_id)
    nl_sock.send_msg(nl_hdr.serialize() + update_msg)
    return ReturnStatus.Continue

def accept_unix_conn(unix_sock: IPCSocket, poller: Poller):
    client: IPCSocket = unix_sock.accept()
    # deal with init message
    message = client.read()
    message = json.loads(message)
    info = int(message.get("type", -1))
    if info != MessageType.INIT.value:
        log.error("Incorrect message type: {}, ignore this".format(info))
        return ReturnStatus.Continue
    # accept new conn and register to poller
    flow_id = int(message["flow_id"])
    log.info(
        "Spine get connection from Env, flow_id is {}, new ipc fd: {}".format(
            flow_id, client.fileno()
        )
    )
    client.set_noblocking()
    # unix_sock: recv updated parameters and relay to nl_sock
    unix_read_wrapper = partial(read_unix_message, client)
    poller.add_action(
        Action(client, PollEvents.READ_ERR_FLAGS, callback=unix_read_wrapper)
    )
    return ReturnStatus.Continue



def polling(poller: Poller):
    while not cont.is_set():
        if poller.poll_once() == False:
            # just sleep for a while (10ms)
            time.sleep(0.01)


def main(args):
    poller = Poller()
    # register accept for unix socket
    listen_callback = partial(accept_unix_conn, unix_sock)
    poller.add_action(
        Action(
            unix_sock,
            PollEvents.READ_ERR_FLAGS,
            callback=listen_callback,
        )
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
