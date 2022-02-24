import socket
import os
import sys
import struct

MAX_PAYLOAD_LEN = 1024
STATE = 6
PARAM = 7
NEURAL_NETWORK = 8


def main():
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_USERSOCK)
    # bind
    assert (sock.fileno() > 0, "Invalid socket fileno")
    pid = os.getpid()
    sock.bind((pid, 0))

    # send message to kernel
    """ prepare netlink header (16 bytes)
    0               1               2               3
    0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Length                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Type              |           Flags              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Process ID (PID)                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    nl_header = struct.pack("=IHHII", MAX_PAYLOAD_LEN, 0, 0, 0, pid)
    # send Param message

    # payload format: cubic_alpha(u32) + cubic_beta(u32) + message(char[64])
    msg = "Hello from userspace python!"
    payload = struct.pack("=II64s", 10, 20, msg.encode())
    print("Payload len: {}".format(len(payload)))
    print(
        "Send to kernel: cubic_alpha:{}, cubic_beta:{}, message:{}".format(10, 20, msg)
    )
    """ Message header (8 bytes) format 
        type(u16) + len(u16) + sock(u32)
    """
    message_header = struct.pack("=HHI", PARAM, 8 + len(payload), sock.fileno())
    # combine message
    message = nl_header + message_header + payload
    # to kernel
    sock.sendto(message, (0, 0))
    # recv reply
    data = sock.recv(1024)
    # read header
    msg_len, msg_type, flags, seq, pid = struct.unpack("=IHHII", data[:16])
    if pid != 0:
        print("Wrong message")
        sys.exit(-1)
    print("We receive message from kernel")
    # kernel reply with header(8 bytes) + StateMsg
    # State message format: number(u32) + message(char[])
    h_type, h_len, sockid = struct.unpack("=HHI", data[16:24])
    reply_num = struct.unpack("=I", data[24:28])
    message = data[28:48]
    print("Recv from kernel: number: {}; message: {}".format(reply_num, message))


if __name__ == "__main__":
    main()
