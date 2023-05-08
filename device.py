# created 2023-04-27 by Zane Globus-O'Harra
# 

import time
import hashlib, hmac

import deviceutils


# {"user" : key} (these are entered into the table the first time the 
# user logs in with their account on the device)
SECRET_KEY_TABLE = {} 

# host/port info for the validation server.
# fixed here
# production version could read from file, user input, or scanned QR code
HOST = "127.0.0.1"
PORT = 65432

# functions to get user and key info
# fixed returns for this version
# production version could select user via input or QR code
# and key from stored key(s)
def get_user():
    return "test_user"


def get_key():
    return "test_key"


# function to return an identifier
# for testing, using a fixed value
# for production, prompt for user entry or use command line
def get_identifier():
    # return 123456
    val = int(input("Enter identifier: "))
    return val

    
# alternate version using 
def generate_pin(identifier):
    time_s = int(time.time()) # get the time since epoch in seconds
    # print(time_s)
    msg = str(time_s ^ identifier)
    h = hmac.new(
        get_key().encode('utf-8'), 
        msg.encode('utf-8'), 
        hashlib.sha256
    )
    return h.hexdigest()


def main():
    id = get_identifier()
    user = get_user()
    pin = generate_pin(id)
    # print("Generated PIN: ", pin)
    deviceutils.send_message(HOST, PORT, user, pin)


if __name__ == "__main__":
    main()