"""
2D2FA device

Get the network information (host, port), as well as the user
information and the one-time identifier created by the server. Generate
a PIN based on the identifier, the current time, and using the user's
secret key as the hash key. Send this PIN to the server for
verification. 

created 2023-04-27 by Zane Globus-O'Harra
"""

import time
import hashlib, hmac

import deviceutils


# set True to show connection and message info, False to hide
DEBUG = False

# {"user" : key} (these are entered into the table the first time the 
# user logs in with their account on the device)
SECRET_KEY_TABLE = {} 

TIME_SLICE = 30 # a time slice is 30s as defined in the 2d-2fa paper

# host/port info for the validation server.
# fixed here
# production version could read from file, user input, or scanned QR code
HOST = "127.0.0.1"
PORT = 65432


def get_user():
    """
    Dummy function for getting the user. Currently only the default
    'test_user' is returned in this version. 

    production version could select user via input and the key from
    stored key(s)
    """
    return "test_user"


def get_key():
    """
    Get the secret key associated with a user. This is read in from the
    disk and provided to the pin generation algorithm.
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
    key = get_key()

    h = hmac.new(
        key.encode('utf-8'), 
        msg.encode('utf-8'), 
        hashlib.sha256
    )

    return h.hexdigest()


def main():
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


if __name__ == "__main__":
    main()
