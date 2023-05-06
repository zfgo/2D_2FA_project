# 2D2FA Server Code
# created 2023-05-05 by Doug Ure

# TCP connection and messaging code modified from:
# https://realpython.com/python-sockets/


import sys
import socket
import selectors
import traceback
import time

import serverutils

# how long an authorization is good for, in seconds
TIMEOUT = 120

# time between server ticks in seconds
TICK = 1

sel = selectors.DefaultSelector()

# "authorized" list: maps username to time of authorization
auth = {}


def timeout_auth():
    expire = int(time.time()) - TIMEOUT
    for x in auth.copy():
        # print("Checking ", x, " ", auth[x], " against time ", expire)
        if auth[x] < expire:
            # print(x, " has expired!")
            auth.pop(x)


def accept_wrapper(sock):
    conn, addr = sock.accept()  # Should be ready to read
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    message = serverutils.Message(sel, conn, addr)
    sel.register(conn, selectors.EVENT_READ, data=message)


if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <host> <port>")
    sys.exit(1)

host, port = sys.argv[1], int(sys.argv[2])
lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Avoid bind() exception: OSError: [Errno 48] Address already in use
lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
lsock.bind((host, port))
lsock.listen()
print(f"Listening on {(host, port)}")
lsock.setblocking(False)
sel.register(lsock, selectors.EVENT_READ, data=None)

try:
    while True:
        events = sel.select(timeout=TICK)
        for key, mask in events:
            if key.data is None:
                accept_wrapper(key.fileobj)
            else:
                message = key.data
                try:
                    message.process_events(mask, auth)
                except Exception:
                    print(
                        f"Main: Error: Exception for {message.addr}:\n"
                        f"{traceback.format_exc()}"
                    )
                    message.close()
        # server "tick" actions go here
        # set timeout to some small value above
        # print("Tick!")
        timeout_auth()
except KeyboardInterrupt:
    print("Caught keyboard interrupt, exiting")
finally:
    sel.close()
