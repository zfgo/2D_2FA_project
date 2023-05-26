"""
2D2FA Server Code
created 2023-05-05 by Doug Ure

TCP connection and messaging code modified from:
https://realpython.com/python-sockets/
"""


import sys
import socket
import selectors
import traceback
import time
import threading
from threading import Thread, RLock
import serverutils
import flask
from flask import Flask, redirect, url_for, request


app = Flask(__name__)

lock = RLock()

# set to True to show connection and message info, False to hide
DEBUG = True

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
#keys = {}
#keys.update({"test_user": "test_key"})
keys = serverutils.get_keys()

# "authorized" list: maps username to time of authorization
auth = {}

# "identifier" list: maps username to an array containing an identifier and timeout
# { username : [identifier, timeout]
ident = {}


"""
================
APIs
================
"""

@app.route('/index')
def index():
    print("Index called")
    r = name_request_text()
    r += '</body></html>'
    print("Index response: ", r)
    return r


@app.route('/checkname', methods = ["POST", "GET"])
def checkname():
    print("Checkname called")
    if request.method == "POST":
        target_name = request.form["username"]
    else:
        target_name = request.args.get("username")
    r = name_request_text()
    if target_name not in keys.keys():
        r += '<p style="color: #FF0000">User ' + target_name + ' not found</p>'
    else:
        # user exists, state if they are authenticated
        if target_name in auth.keys():
            r+= '<p style="color: #00FF00">User ' + target_name + ' is authorized</p>'
        else:
            r+= '<p style="color: #FF0000">User ' + target_name + ' is not authorized</p>'
        # get an identifier
        expire = int(time.time()) - IDENT_TIMEOUT + MIN_TIME
        with lock:
            r_id = 0
            # first check if identifier exists
            if target_name in ident.keys():
                #check it hasn't expired, generate new 
                if ident[target_name][1] > expire:
                    r_id = ident[target_name][0]
                else:
                    r_id = make_new_key(target_name)
            else:
                r_id = make_new_key(target_name)
        r += '<p style="font-size:24px; ">' + str(r_id).zfill(6) + '</p>'
    r += '</body></html>'
    print("Checkname response: ", r)
    return r
        


"""
================
Code
================
"""


def make_new_key(uname):
    nid = serverutils.generate_identifier()
    newtime = int(time.time())
    ident.update({uname: [nid, newtime]})
    return nid


def name_request_text():
    """
    function generates the opening text common to all HTML replies
    """
    resp = '<html><body><form action="checkname" mothod="POST">'
    resp += '<label>Input user name: </label>'
    resp += '<input type="text" name="username">'
    resp += '<input type="submit" value="submit" name="submit"></form>'
    return resp


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
                ident.pop(y)


def accept_wrapper(sock):
    conn, addr = sock.accept()  # Should be ready to read
    if DEBUG:
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

"""
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
                    print(f"Identifier for {val}: {ident[val][0]:06d}")
                    # restart loop
                    continue
            # identifier not found or expired, generate a new one:
            newid = serverutils.generate_identifier()
            newtime = int(time.time())
            ident.update({val: [newid, newtime]})
            print(f"Identifier for {val}: {ident[val][0]:06d}")
            if DEBUG:
                print("Ident list: ", ident)
"""

def user_ident_thread():
    app.debug = False
    app.run(port = 5001)


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)

    if DEBUG:
        print("Got keys: ", keys)
        print("test_user's key: ", keys["test_user"])
    host, port = sys.argv[1], int(sys.argv[2])
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Avoid bind() exception: OSError: [Errno 48] Address already in use
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        lsock.bind((host, port))
        #lsock.bind(("", port))
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
        #app.debug = True
        #app.run()
        t1.join()
       #t2.join()
    except KeyboardInterrupt:
        print("Caught keyboard interrupt, exiting")
    finally:
        sel.close()


if __name__ == "__main__":
    main()
