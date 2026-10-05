#!/usr/bin/env python3
"""
sluicify — reference Python client for the sluice broker. Stdlib only,
demonstrates that the in-sandbox surface required to talk to sluice is
just `socket.send_fds` + a tiny binary frame. Wire format mirrors
`src/proto.rs`.

Usage:
    sluicify.py /run/sluice.sock git log --oneline -n 5
"""

import socket
import struct
import sys

MAGIC   = 0x534C4358
VERSION = 1
ERR_TIMEOUT = -7


def call(sock_path, argv):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    s.connect(sock_path)

    # Encode request.
    parts = [struct.pack("<III", MAGIC, VERSION, len(argv))]
    for a in argv:
        b = a.encode("utf-8")
        parts.append(struct.pack("<I", len(b)))
        parts.append(b)
    payload = b"".join(parts)

    # Send payload + our 0/1/2 fds.
    socket.send_fds(s, [payload], [0, 1, 2])

    # Read reply: magic, version, status (i32).
    reply = s.recv(4096)
    if len(reply) < 12:
        sys.exit("sluice: short reply")
    magic, version, status = struct.unpack("<IIi", reply[:12])
    if magic != MAGIC or version != VERSION:
        sys.exit(f"sluice: bad reply magic/version: {magic:#x}/{version}")
    if status >= 0:
        sys.exit(status)
    sys.exit(124 if status == ERR_TIMEOUT else min(128 - status, 255))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("usage: sluicify.py <socket> <cmd> [args...]")
    call(sys.argv[1], sys.argv[2:])
