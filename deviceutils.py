"""
2D2FA Device Utilities

TODO

created 2023-05-05 by Doug Ure

TCP connection and messaging code modified from:
https://realpython.com/python-sockets/
"""

import sys
import socket
import selectors
import traceback
import json
import io
import struct


sel = selectors.DefaultSelector()

# set to True to show connection and message info, False to hide
DEBUG = False


def create_request(user, pin):
    """
    Create a request, which is a dict in the following format:
    ```
    {
        "type": "text/json",
        "encoding": "utf-8",
        "content": {
            "user": user,
            "pin": pin,
        },
    }
    ```
    It has a default type and encoding, but takes in the user's name and
    the generated pin as arguments.
    """
    return dict(
        type="text/json",
        encoding="utf-8",
        content=dict(user=user, pin=pin),
    )


def start_connection(host, port, request):
    """
    Connect to the server to send a message. Get the correct address
    from the host and port from the user, and connect to a remote socket
    at the address. Create a Message object to send over the connection
    and register it.
    """
    addr = (host, port) # get the address

    if DEBUG:
        print(f"Starting connection to {addr}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    sock.connect_ex(addr) # connect to the remote socket at the address
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    message = Message(sel, sock, addr, request) # create the message

    sel.register(sock, events, data=message)


def send_message(host, port, user, pin):
    """
    Create a request that will be sent over the connection, start the
    connection, and send the message over the connection. Close the
    scoket and unregister the message when complete.
    """
    request = create_request(user, pin)
    start_connection(host, port, request)

    try:
        while True:
            events = sel.select(timeout=1)

            # for each message, attempt to send it over the network
            for key, mask in events:
                message = key.data
                try:
                    # send the message over the network
                    message.process_events(mask)

                except Exception:
                    print(
                        f"Main: Error: Exception for {message.addr}:\n"
                        f"{traceback.format_exc()}"
                    )
                    message.close()
            # Check for a socket being monitored to continue.
            if not sel.get_map():
                break
    
    except KeyboardInterrupt:
        print("Caught keyboard interrupt, exiting")

    finally:
        # close the selector
        sel.close()


class Message:
    """
    A class to represent a message and network connection, capable of
    sending the message over the network to a server, and closing the
    socket over which the message was sent. 
    """
    def __init__(self, selector, sock, addr, request):
        """
        The Message class initializer initializes the following
        attributes:

        - selector: A selector object for "high-level and efficient I/O
        - multiplexing." This determines if a message is available for
          reading or writing. 
        - sock: The socket that provides the connection to the server.
        - addr: The address of the server to which the socket is
          connected.
        - request: The 'request' data structure created by
          `create_request()`.
        - _recv_buffer: Buffer into which data is read from the socket
          connection. 
        - _send_buffer: Buffer into which data is written before it is
          sent over the connection.
        - _request_queued: Boolean indicating whether a request has been
          queued for sending over the network.
        - _jsonheader_len: The length of a `jsonheader`.
        - jsonheader: The header of a message that is to be sent over
          the network.
        - response: The response from the server.
        """
        self.selector = selector
        self.sock = sock
        self.addr = addr
        self.request = request
        self._recv_buffer = b""
        self._send_buffer = b""
        self._request_queued = False
        self._jsonheader_len = None
        self.jsonheader = None
        self.esponse = None

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

    def _process_response_json_content(self):
        """
        Helper function to process JSON header content.
        """
        content = self.response
        result = content.get("result")
        print(f"Got result: {result}")

    def _process_response_binary_content(self):
        """
        Helper function to process binary content.
        """
        content = self.response
        print(f"Got response: {content!r}")

    def process_events(self, mask):
        """
        Based on the mask set in the selector, either write to or read
        from the network.
        """
        if mask & selectors.EVENT_READ:
            self.read()
        if mask & selectors.EVENT_WRITE:
            self.write()

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
            if self.response is None:
                self.process_response()

    def write(self):
        """
        Write to the network. Queue a request, and the call the helper
        function to send the message over the socket connection.
        """
        if not self._request_queued:
            self.queue_request()

        self._write()

        if self._request_queued:
            if not self._send_buffer:
                # Set selector to listen for read events, we're done writing.
                self._set_selector_events_mask("r")

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

    def queue_request(self):
        """
        Queue a request for sending. Create the message header and pack
        it with the message by calling the `_create_message()` helper.
        Then, pack the message into the `_send_buffer` and set the
        `_request_queued` indicator.
        """
        content = self.request["content"]
        content_type = self.request["type"]
        content_encoding = self.request["encoding"]
        if content_type == "text/json":
            req = {
                "content_bytes": self._json_encode(content, content_encoding),
                "content_type": content_type,
                "content_encoding": content_encoding,
            }
        else:
            req = {
                "content_bytes": content,
                "content_type": content_type,
                "content_encoding": content_encoding,
            }
        message = self._create_message(**req)
        self._send_buffer += message
        self._request_queued = True

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

    def process_response(self):
        """
        Process a response based on the header type of the received
        message. Once the message has been processed, close the socket
        connection. 
        """
        content_len = self.jsonheader["content-length"]
        if not len(self._recv_buffer) >= content_len:
            return
        data = self._recv_buffer[:content_len]
        self._recv_buffer = self._recv_buffer[content_len:]
        if self.jsonheader["content-type"] == "text/json":
            encoding = self.jsonheader["content-encoding"]
            self.response = self._json_decode(data, encoding)
            if DEBUG:
                print(f"Received response {self.response!r} from {self.addr}")
            self._process_response_json_content()
        else:
            # Binary or unknown content-type
            self.response = data
            if DEBUG:
                print(
                    f"Received {self.jsonheader['content-type']} "
                    f"response from {self.addr}"
                )
            self._process_response_binary_content()
        # Close when response has been processed
        self.close()
