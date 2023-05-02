# created 2023-04-27 by Zane Globus-O'Harra
# 

import time
import hashlib, hmac


# {"user" : key} (these are entered into the table the first time the 
# user logs in with their account on the device)
SECRET_KEY_TABLE = {} 


def generate_pin(identifier, user):
    time_s = int(time.time()) # get the time since epoch in seconds
    msg = str(time_s ^ identifier)
    h = hmac.new(
        SECRET_KEY_TABLE[user].encode('utf-8'), 
        msg.encode('utf-8'), 
        hashlib.sha256
    )
    return h.hexdigest()


def main():
    user = "zfg@uoregon.edu" # this will be received from the server
    key = "test key" # this will be in the SECRET_KEY_TABLE associated with user

    SECRET_KEY_TABLE[user] = key

    identifier = 123456 # this will be received from the server

    hexdigest = generate_pin(identifier, user) # the hex digest will be sent back to the server for verification

    print(hexdigest)


if __name__ == "__main__":
    main()