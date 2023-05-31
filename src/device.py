"""
2D2FA device

Get the network information (host, port), as well as the user
information and the one-time identifier created by the server. Generate
a PIN based on the identifier, the current time, and using the user's
secret key as the hash key. Send this PIN to the server for
verification. 

Also generate HTML for a simple browser interface.

created 2023-04-27 by Zane Globus-O'Harra
2023-05-28 Zane Globus-O'Harra add docstrings
"""

import time
import hashlib, hmac
import json
import flask
from flask import Flask, redirect, url_for, request

import deviceutils


app = Flask(__name__)


# set True to show connection and message info, False to hide
DEBUG = False

# {"user" : key} (these are entered into the table the first time the 
# user logs in with their account on the device)
SECRET_KEY_TABLE = {} 

TIME_SLICE = 30 # a time slice is 30s as defined in the 2d-2fa paper

host = "127.0.0.1"
port = 65432
keys = []
user = ""
key = ""


"""
================
APIs
================
"""

@app.route('/index')
def index():
    # return "Landing page"
    return selection_menu()


@app.route('/enter_id', methods = ["POST"])
def enter_id():
    #return "Success?"
    index = int(request.form["hostindex"])
    #return ("Got index " + index)
    id_process(index)
    resp = '<html><body><form action="do_auth" method="POST">'
    resp += '<label>Input identifier: </label>'
    resp += '<input type="text" name="ident">'
    resp += '<input type="submit" value="submit" name="submit"></form>'
    #resp += '<br><form action="/index" method="GET"><input type="submit" value="return" name="return"'
    #resp += '</form></body></html>'
    resp += '<a href="index">Select different host/user</a>'
    resp += '</body></html>'
    return resp


@app.route('/do_auth', methods = ["POST"])
def do_auth():
    #return "Success?"
    ident = int(request.form["ident"])
    auth_process(ident)
    resp = '<html><body>PIN sent<br>Check login page'
    resp += '<br><a href="index">Select different host/user</a>'
    resp += '<br><a href="enter_id">Input different identifier</a>'
    resp += '</body></html>'
    return resp


"""
================
Code
================
"""


def load_keylist():
    """
    load the list of hosts, addresses, ports, usernames, and keys from an external file
    each line is a single json for one entry
    format: hostname, address, port, user, key
    """
    f = open('device_user_list.txt')
    for line in f:
        keys.append(json.loads(line))


def selection_menu():
    resp = '<html><body><form action="enter_id" method="POST">'
    resp += '<label>Select host name:</label>'
    resp += '<select name="hostindex">'
    count = 0
    for line in keys:
        name = line["hostname"] + " : " + line["user"]
        resp += '<option value=' + str(count) + '> ' + name + '</option>'
        count += 1
    resp += '</select>'
    resp += '<input type="submit" value="submit" name="submit">'
    resp += '</form></body></html>'
    return resp


def id_process(index):
    target = keys[index]
    global host
    global port
    global user
    global key
    host = target["address"]
    port = target["port"]
    user = target["user"]
    key = target["key"]


def auth_process(ident):
    pin = generate_pin(ident)
    deviceutils.send_message(host, port, user, pin)
    


def get_user():
    """
    Dummy function for getting the user. Currently only the default
    'test_user' is returned in this version. 

    production version could select user via input and the key from
    stored key(s)
    NOW UNUSED
    """
    return "test_user"


def get_key():
    """
    Get the secret key associated with a user. This is read in from the
    disk and provided to the pin generation algorithm.
    NOW UNUSED
    """
    return "test_key"


def get_identifier():
    """
    function for getting an identifier as input from the user, already
    created and provided by the server.
    """
    val = int(input("Enter identifier: "))
    return val


def set_host():
    """
    Get the host IP address. If no host is specified (empty string is 
    entered), then the default host is returned (127.0.0.1)
    NOW UNUSED
    """
    h = input("Enter host address: ")

    if h == "":
        # return default local host if no host specified
        return "127.0.0.1"

    return h


def set_port():
    """
    Set the port. The user must enter the same port that the server is
    running on for a connection to be established. If no port is
    specified (empty string is entered), then a default port of 4444 is
    returned. 
    NOW UNUSED
    """
    entered = input("Enter port number: ")
    if entered == "":
        # return default port of 4444 if no host specified
        return 4444

    return int(entered)


def generate_pin(identifier):
    """
    Generate a pin using the entered identifier, the time, and the
    user's secret key. This is done using the SHA256 hash algorithm.
    This generated pin is sent to the server to be verified.
    """
    time_s = int(time.time()) # get the time since epoch in seconds
    time_slice = time_s // TIME_SLICE # get the time, divide to get current slice
    
    if DEBUG:
        print(f"Current time: {time_s}; Time slice: {time_slice}")

    msg = str(time_slice ^ identifier)
    #key = current_key

    h = hmac.new(
        key.encode('utf-8'), 
        msg.encode('utf-8'), 
        hashlib.sha256
    )

    return h.hexdigest()


def main():
    load_keylist()
    
    if DEBUG:
        print("Keylist: ", keys)
        print("First user: ", keys[0]["user"])
    
    app.debug = True
    app.run()
    """
    # set the host and port
    host = set_host()
    port = set_port()

    # get the user and the identifier
    user = get_user()
    id = get_identifier()

    # generate the pin
    pin = generate_pin(id)
    # send the pin to the server
    deviceutils.send_message(host, port, user, pin)
    """


if __name__ == "__main__":
    main()
