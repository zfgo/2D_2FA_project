# 2D2FA Server Code
# created 2023-05-05 by Doug Ure

# TCP connection and messaging code modified from:
# https://realpython.com/python-sockets/


import sys
import socket
import selectors
import traceback
import time

#import multiprocessing
#from multiprocessing import Process, Manager

import threading
from threading import Thread, RLock

import serverutils

lock = RLock()


# set 1 to show connection and message info, 0 to hide
DEBUG = 0

# how long an authorization is good for, in seconds
AUTH_TIMEOUT = 120

# how long an ID is good for, in seconds
IDENT_TIMEOUT = 120

# minimum timeout length when requesting an identifier
# if current timeout is less than this, generate a new identifier
# this is to avoid users entering an identifier only to find it has
# expired before they could do so
MIN_TIME = 30

# time between server ticks in seconds
TICK = 1

sel = selectors.DefaultSelector()


# "keys" list: maps users to secret keys
# for testing purposes, is populated here
# for production, likely would need to populate this by reading from file on startup
keys = {}
keys.update({"test_user": "test_key"})


# "authorized" list: maps username to time of authorization
auth = {}


# "identifier" list: maps username to an array containing an identifier and timeout
# { username : [identifier, timeout]
ident = {}


def timeout_auth():
    expire = int(time.time()) - AUTH_TIMEOUT
    with lock:
        for x in auth.copy():
            # print("Checking ", x, " ", auth[x], " against time ", expire)
            if auth[x] < expire:
                # print(x, " has expired!")
                auth.pop(x)


def timeout_id():
    expire = int(time.time()) - IDENT_TIMEOUT
    with lock:
        for y in ident.copy():
            if ident[y][1] < expire:
                ident.pop(x)


def accept_wrapper(sock):
    conn, addr = sock.accept()  # Should be ready to read
    if DEBUG == 1:
        print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    message = serverutils.Message(sel, conn, addr)
    sel.register(conn, selectors.EVENT_READ, data=message)


def auth_listen():
    while True:
        events = sel.select(timeout=TICK)
        for key, mask in events:
            if key.data is None:
                accept_wrapper(key.fileobj)
            else:
                message = key.data
                try:
                    message.process_events(mask, auth, ident, keys)
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
        timeout_id()


def user_ident_thread():
    while True:
        val = input("Enter user name: ")
        if val not in keys.keys():
            print("User not found")
            continue
        # user exists, get an identifier
        expire = int(time.time()) - IDENT_TIMEOUT + MIN_TIME
        with lock:
            # first check if an identifier exists
            if val in ident.keys():
                # then check that it hasn't expired, with MIN_TIME margin
                if ident[val][1] > expire:
                    print("Identifier for ", val, ": ", ident[val][0])
                    # restart loop
                    continue
            # identifier not found or expired, generate a new one:
            newid = serverutils.generate_identifier()
            newtime = int(time.time())
            ident.update({val: [newid, newtime]})
            print("Identifier for ", val, ": ", newid)


if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <host> <port>")
    sys.exit(1)

host, port = sys.argv[1], int(sys.argv[2])
lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Avoid bind() exception: OSError: [Errno 48] Address already in use
lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    lsock.bind((host, port))
except socket.error as msg:
    print("Socket binding error: " + str(msg) + "\n")
    sys.exit("Exiting")
lsock.listen()
print(f"Listening on {(host, port)}")
lsock.setblocking(False)
sel.register(lsock, selectors.EVENT_READ, data=None)


try:
    # auth_listen()
    t1 = threading.Thread(target=auth_listen)
    t2 = threading.Thread(target=user_ident_thread)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
except KeyboardInterrupt:
    print("Caught keyboard interrupt, exiting")
finally:
    sel.close()
