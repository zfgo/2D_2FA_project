"""
2D2FA Server Utilities

Utility functions for the server involving the socket connections, and
creating and sending messages, as well as verifying the PIN generated by
the user's device.

created 2023-05-05 by Doug Ure
2023-05-28 Zane Globus-O'Harra add docstrings

TCP connection and messaging code modified from:
https://realpython.com/python-sockets/
"""

import sys
import selectors
import json
import io
import struct
import time
import hashlib, hmac
import secrets # secure random generator
from secrets import SystemRandom    # secure random generator

# set True to show connection and message info, False to hide
DEBUG = False

TIME_SLICE = 30 # a time slice is 30 seconds as defined in the 2d-2fa paper


def get_keys():
    """
    Read a file containing a json mapping users to keys
    """
    f = open('server_user_list.txt')
    for line in f:
        dat = json.loads(line)
        return dat


def get_key(user, keys):
    """
    Look up and return the key for a user. "Production" version should
    read from a file. Test and proof-of-conecpt version can probably just
    use a dictionary defined here.
    """
    k = keys.get(user)
    return k


def generate_identifier():
    """
    Generate a random 6-digit identifier that the user will input on the
    device. Use the `SystemRandom()` function from the secrets library
    to get a secure random generator
    """
    return secrets.randbelow(1_000_000)


def get_identifier(user, ident):
    """
    Get the identifier associated with a user (identifiers expire after
    2 mninutes).
    """
    id = ident.get(user)
    if id is None:
        return None
    return id[0]


def check_pin(user, pin, ident, keys):
    """
    Check the pin for +/- 2 time slices from current time (+/- 60s,
    because each time slice is 30s). If the we generate a pin that
    matches the pin generated by the device, then return True, else
    return False.
    """
    time_now_s = int(time.time()) # get the time since epoch in seconds
    time_slice = time_now_s // TIME_SLICE # get the time, divide into slices
    if DEBUG:
        print("Checking PIN")
        print(f"Current time: {time_now_s}s; Time slice: {time_slice}")
    identifier = get_identifier(user, ident)
    if DEBUG:
        print("Keys: ", keys)
        print("Ident: ", ident)
        print(f"Using identifier for {user}: {identifier}")

    if identifier is None:
        return False
    
    key = get_key(user, keys)
    if DEBUG:
        print("Using key: ", key)
    if key is None:
        return False

    for time_i in range(time_slice-2, time_slice+3): # current time slice +/- two slices (add three to upper end bc of range's indexing)
        msg = str(time_i ^ identifier) # create the message (time + identifier)

        # hash the message using the user's secret key
        h = hmac.new(
            key.encode('utf-8'),
            msg.encode('utf-8'),
            hashlib.sha256
        )

        # if the hash is equal to the pin for any time in the window,
        # return true
        if DEBUG:
            print("Checking timeslice ", time_i, " PIN: ", h.hexdigest())
        if h.hexdigest() == pin:
            return True
    
    # the time limit has expired, return false
    return False


class Message:
    """
    A class to represent a message and network connection, capable of
    sending the message over the network to a server, and closing the
    socket over which the message was sent. 
    """
    def __init__(self, selector, sock, addr):
        """
        The Message class initializer initializes the following
        attributes:

        - selector: A selector object for "high-level and efficient I/O
        - multiplexing." This determines if a message is available for
          reading or writing. 
        - sock: The socket that provides the connection to the server.
        - addr: The address of the server to which the socket is
          connected.
        - _recv_buffer: Buffer into which data is read from the socket
          connection. 
        - _send_buffer: Buffer into which data is written before it is
          sent over the connection.
        - _jsonheader_len: The length of a `jsonheader`.
        - jsonheader: The header of a message that is to be sent over
          the network.
        - request: The 'request' data structure created by
          `create_request()`.
        - response_created: Indicator variable to show whether the
          response has been created or not.
        """
        self.selector = selector
        self.sock = sock
        self.addr = addr
        self._recv_buffer = b""
        self._send_buffer = b""
        self._jsonheader_len = None
        self.jsonheader = None
        self.request = None
        self.response_created = False

    def _set_selector_events_mask(self, mode):
        """
        Set selector to listen for events: mode is 'r', 'w', or 'rw'.
        """
        if mode == "r":
            events = selectors.EVENT_READ
        elif mode == "w":
            events = selectors.EVENT_WRITE
        elif mode == "rw":
            events = selectors.EVENT_READ | selectors.EVENT_WRITE
        else:
            raise ValueError(f"Invalid events mask mode {mode!r}.")
        self.selector.modify(self.sock, events, data=self)

    def _read(self):
        """
        Get data from the socket connection, put it into the
        `_recv_buffer`. 
        """
        try:
            # Should be ready to read
            data = self.sock.recv(4096)
        except BlockingIOError:
            # Resource temporarily unavailable (errno EWOULDBLOCK)
            pass
        else:
            if data:
                self._recv_buffer += data
            else:
                raise RuntimeError("Peer closed.")

    def _write(self):
        """
        If there is data in the `_send_buffer`, send it over the socket
        connection. 
        """
        if self._send_buffer:
            if DEBUG:
                print(f"Sending {self._send_buffer!r} to {self.addr}")
            try:
                # Should be ready to write
                sent = self.sock.send(self._send_buffer)
            except BlockingIOError:
                # Resource temporarily unavailable (errno EWOULDBLOCK)
                pass
            else:
                self._send_buffer = self._send_buffer[sent:]
                # Close when the buffer is drained. The response has been sent.
                if sent and not self._send_buffer:
                    self.close()

    def _json_encode(self, obj, encoding):
        """
        Helper function to encode a JSON object using a specified
        encoding. Return the encoded object.
        """
        return json.dumps(obj, ensure_ascii=False).encode(encoding)

    def _json_decode(self, json_bytes, encoding):
        """
        Helper function to decode a JSON object using a specified
        encoding. Return the decoded object.
        """
        tiow = io.TextIOWrapper(
            io.BytesIO(json_bytes), encoding=encoding, newline=""
        )
        obj = json.load(tiow)
        tiow.close()
        return obj

    def _create_message(
        self, *, content_bytes, content_type, content_encoding
    ):
        """
        Create a message to send over the network by packing the message
        header and the message into a struct. Return the created
        message. 
        """
        jsonheader = {
            "byteorder": sys.byteorder,
            "content-type": content_type,
            "content-encoding": content_encoding,
            "content-length": len(content_bytes),
        }
        jsonheader_bytes = self._json_encode(jsonheader, "utf-8")
        message_hdr = struct.pack(">H", len(jsonheader_bytes))
        message = message_hdr + jsonheader_bytes + content_bytes
        return message

    def _create_response_json_content(self, auth, ident, keys):
        # rewrite, "user" insted of "action"
        # check first that "user" and "pin" exist, abort if not
        action = self.request.get("action")
        if (( "user" in self.request.keys() ) and ( "pin" in self.request.keys() )):
            # check pin/key
            user = self.request.get("user")
            if DEBUG:
                print("In create_response, user = ", user)
            pin = self.request.get("pin")
            content = {}
            if (check_pin(user, pin, ident, keys)):
                # PIN is good!
                time_s = int(time.time())
                auth.update({user: time_s})
                content = {"result": "Authorization granted."}
            else:
                content = {"result": "Authentication failed."}
        else:
            content = {"result": f"Error: invalid action '{action}'."}
        content_encoding = "utf-8"
        response = {
            "content_bytes": self._json_encode(content, content_encoding),
            "content_type": "text/json",
            "content_encoding": content_encoding,
        }
        return response

    def _create_response_binary_content(self):
        """
        Create a response using binary encoding
        """
        response = {
            "content_bytes": b"First 10 bytes of request: "
            + self.request[:10],
            "content_type": "binary/custom-server-binary-type",
            "content_encoding": "binary",
        }
        return response

    def process_events(self, mask, auth, ident, keys):
        """
        Based on the mask set in the selector, either write to or read
        from the network.
        """
        if mask & selectors.EVENT_READ:
            self.read()
        if mask & selectors.EVENT_WRITE:
            self.write(auth, ident, keys)

    def read(self):
        """
        Call the `_read()` helper function, then process the header
        received from the server and process the response. 
        """
        self._read()

        if self._jsonheader_len is None:
            self.process_protoheader()

        if self._jsonheader_len is not None:
            if self.jsonheader is None:
                self.process_jsonheader()

        if self.jsonheader:
            if self.request is None:
                self.process_request()

    def write(self, auth, ident, keys):
        """
        Write to the network. Queue a request, and the call the helper
        function to send the message over the socket connection.
        """
        if self.request:
            if not self.response_created:
                self.create_response(auth, ident, keys)

        self._write()

    def close(self):
        """
        Close the socket connection to an address.
        """
        if DEBUG:
            print(f"Closing connection to {self.addr}")
        try:
            self.selector.unregister(self.sock)
        except Exception as e:
            print(
                f"Error: selector.unregister() exception for "
                f"{self.addr}: {e!r}"
            )

        try:
            self.sock.close()
        except OSError as e:
            print(f"Error: socket.close() exception for {self.addr}: {e!r}")
        finally:
            # Delete reference to socket object for garbage collection
            self.sock = None

    def process_protoheader(self):
        hdrlen = 2
        if len(self._recv_buffer) >= hdrlen:
            self._jsonheader_len = struct.unpack(
                ">H", self._recv_buffer[:hdrlen]
            )[0]
            self._recv_buffer = self._recv_buffer[hdrlen:]

    def process_jsonheader(self):
        """
        Process a JSON message header. Decode the json, and set crop the
        `_recv_buffer` so that the message header is excluded from the
        actual message contents.
        """
        hdrlen = self._jsonheader_len
        if len(self._recv_buffer) >= hdrlen:
            self.jsonheader = self._json_decode(
                self._recv_buffer[:hdrlen], "utf-8"
            )
            self._recv_buffer = self._recv_buffer[hdrlen:]
            for reqhdr in (
                "byteorder",
                "content-length",
                "content-type",
                "content-encoding",
            ):
                if reqhdr not in self.jsonheader:
                    raise ValueError(f"Missing required header '{reqhdr}'.")

    def process_request(self):
        """
        When a request is received, decode the JSON header and the
        request. Set `self.request` equal to the decoded data.
        """
        content_len = self.jsonheader["content-length"]
        if not len(self._recv_buffer) >= content_len:
            return
        data = self._recv_buffer[:content_len]
        self._recv_buffer = self._recv_buffer[content_len:]
        if self.jsonheader["content-type"] == "text/json":
            encoding = self.jsonheader["content-encoding"]
            self.request = self._json_decode(data, encoding)
            if DEBUG:
                print(f"Received request {self.request!r} from {self.addr}")
        else:
            # Binary or unknown content-type
            self.request = data
            if DEBUG:
                print(
                    f"Received invalid message from {self.addr}"
                )
        # Set selector to listen for write events, we're done reading.
        self._set_selector_events_mask("w")

    def create_response(self, auth, ident, keys):
        """
        Create a response using the user's authentication, the
        identifier, and the user's keys. Encode this as binary, and
        enqueue it for sending.
        """
        if self.jsonheader["content-type"] == "text/json":
            response = self._create_response_json_content(auth, ident, keys)
        else:
            # Binary or unknown content-type
            response = self._create_response_binary_content()
        message = self._create_message(**response)
        self.response_created = True
        self._send_buffer += message
