import os
import sys
import json
import argparse 
import threading
import functools
from functools import partial


from logger import logger as log
from message import *
from netlink import Netlink
from python.src.ipc_socket import IPCSocket
from spine_flow import Flow, active_flowmap
from poller import Action, Poller, ReturnStatus, PollEvents

# communication between spine-user-space and kernel 
nl_sock = None
# communication between spine-user-space and Env
unix_sock = None
# cont status of polling 
cont = threading.Event()

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
    # TODO add semantics to deal with netlink messages
    pass

def read_unix_message(unix_sock: IPCSocket, flow_id):
    raw = unix_sock.read(header=True)
    if raw == None:
        return ReturnStatus.Cancel
    data = json.load(raw)
    # specific for cubic 
    cubic_beta = int(data["cubic_data"])
    cubic_bic_scale = int(data["cubic_bic_scale"])
    msg = UpdateMsg()
    msg.add_field(UpdateField().create(VOLATILE_CONTROL_REG, CUBIC_BETA_REG, cubic_beta))
    msg.add_field(UpdateField().create(VOLATILE_CONTROL_REG, CUBIC_BIC_SCALE_REG, cubic_bic_scale))
    update_msg = msg.serialize()
    nl_hdr = SpineMsgHeader()
    nl_hdr.create(CREATE, len(update_msg) + nl_hdr.hdr_len, flow_id)
    nl_sock.send_msg(nl_hdr.serialize() + update_msg)

def polling(poller: Poller):
    while not cont.is_set():
        poller.poll_once()

def main(args):
    poller = Poller()
    # unix_sock: recv updated parameters and relay to nl_sock
    poller.add_action(Action(unix_sock, PollEvents.READ_ERR_FLAGS, callback=read_unix_message))
    # recv new spine flow info and misc
    poller.add_action(Action(nl_sock, PollEvents.READ_ERR_FLAGS, callback=read_netlink_message))
    threading.Thread(target=polling, args=(poller)).run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ipc", "-i", type=str, required=True, help="IPC communication between Env and Spine controller")
    parser.add_argument("--")
    args = parser.parse_args()
    # build communication sockets
    unix_sock = build_unix_sock(args.ipc)
    nl_sock = build_netlink_sock()

    main(args)