import os
import sys
import json

from logger import logger as log
import message
from message import *
from netlink import Netlink


vanilla_action_keys = {
    "vanilla_alpha",
    "vanilla_beta",
    "vanilla_gamma",
    "vanilla_delta",
}


def send_scubic_message(data: dict, nl_sock: Netlink, sock_id):
    if "cubic_beta" in data["action"] and "cubic_bic_scale" in data["action"]:
        cubic_beta = int(data["action"]["cubic_beta"])
        cubic_bic_scale = int(data["action"]["cubic_bic_scale"])
        # log.info(
        #     "cubic_beta: {}, cubic_bic_scale: {}".format(cubic_beta, cubic_bic_scale)
        # )
        msg = UpdateMsg()
        msg.add_field(
            UpdateField().create(VOLATILE_CONTROL_REG, CUBIC_BETA_REG, cubic_beta)
        )
        msg.add_field(
            UpdateField().create(
                VOLATILE_CONTROL_REG, CUBIC_BIC_SCALE_REG, cubic_bic_scale
            )
        )
        update_msg = msg.serialize()
        nl_hdr = SpineMsgHeader()
        nl_hdr.create(UPDATE_FIELDS, len(update_msg) + nl_hdr.hdr_len, sock_id)
        nl_sock.send_msg(nl_hdr.serialize() + update_msg)
        # log.info("send control to kernel flow: {}".format(sock_id))


def send_vanilla_message(action: dict, nl_sock: Netlink, sock_id):
    for key in vanilla_action_keys:
        if key not in action:
            log.error("no such key: {}".format(key))
            return

    msg = UpdateMsg()
    for key in vanilla_action_keys:
        postfix = key.split("_")[1]
        reg_name = "VANILLA_{}_REG".format(postfix.upper())
        reg = getattr(message, reg_name)
        msg.add_field(UpdateField().create(VOLATILE_CONTROL_REG, reg, action[key]))

    update_msg = msg.serialize()
    nl_hdr = SpineMsgHeader()
    nl_hdr.create(UPDATE_FIELDS, len(update_msg) + nl_hdr.hdr_len, sock_id)
    nl_sock.send_msg(nl_hdr.serialize() + update_msg)
    # log.info("send control to kernel flow: {}".format(sock_id))
