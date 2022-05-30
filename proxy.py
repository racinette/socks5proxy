import logging
import signal
from typing import Tuple, Optional, Callable
from gevent import joinall
from gevent import signal_handler
from gevent import spawn
from gevent import socket
from gevent.server import StreamServer


PROTOCOL_VERSION = b'\x05'

NO_AUTH_METHOD = b'\x00'
GSSAPI_METHOD = b'\x01'
USERNAME_PASSWORD_METHOD = b'\x02'
NO_ACCEPTABLE_METHODS = b'\xFF'

# when client sends authentication methods and none of them match the accepted ones
HANDSHAKE_FAILURE_MESSAGE = PROTOCOL_VERSION + NO_ACCEPTABLE_METHODS

# client commands
CONNECT_CMD = b'\x01'
BIND_CMD = b'\x02'
UPD_ASSOCIATE_CMD = b'\x03'

# server replies
SUCCEEDED_REPLY = b'\x00'
SERVER_FAILURE_REPLY = b'\x01'
CONNECTION_NOT_ALLOWED_REPLY = b'\x02'
NETWORK_UNREACHABLE_REPLY = b'\x03'
HOST_UNREACHABLE_REPLY = b'\x04'
CONNECTION_REFUSED_REPLY = b'\x05'
TTL_EXPIRED_REPLY = b'\x06'
CMD_NOT_SUPPORTED_REPLY = b'\x07'
ADDRESS_TYPE_NOT_SUPPORTED_REPLY = b'\x08'

# reserved
RSV = b'\x00'

# address types
IPv4_ADDRESS_TYPE = b'\x01'
DOMAIN_NAME_ADDRESS_TYPE = b'\x03'
IPv6_ADDRESS_TYPE = b'\x04'

EMPTY_IPv4 = b'\x00\x00\x00\x00'
PORT_0 = b'\x00\x00'

USERNAME_PASSWORD_AUTH_FAILED = b'\x01\x01'
USERNAME_PASSWORD_AUTH_SUCCESS = b'\x01\x00'


def server_print(msg):
    print(f"[SERVER]: {msg}")


def form_reply(rep: bytes, atyp: bytes, bnd_addr: bytes, bnd_port: bytes) -> bytearray:
    assert len(rep) == 1
    assert len(atyp) == 1
    if atyp == IPv4_ADDRESS_TYPE:
        assert len(bnd_addr) == 4
    elif atyp == IPv6_ADDRESS_TYPE:
        assert len(bnd_addr) == 16
    elif atyp == DOMAIN_NAME_ADDRESS_TYPE:
        assert len(bnd_addr) - 1 == bnd_addr[0]
    else:
        raise AssertionError(f"Address Type is: {atyp}, but {bnd_addr} was provided.")
    assert len(bnd_port) == 2
    arr = bytearray()
    arr += PROTOCOL_VERSION
    arr += rep
    arr += RSV
    arr += atyp
    arr += bnd_addr
    arr += bnd_port
    return arr


def socket_is_open(s: socket.socket) -> bool:
    return s.fileno() != -1


def forward(src: socket.socket, dst: socket.socket) -> None:
    try:
        # either socket might close since the other coroutine has them too
        while socket_is_open(src) and socket_is_open(dst):
            data = src.recv(1024)
            if not data:
                break
            dst.sendall(data)
    except Exception as ex:
        logger.error(ex)


# logger
logging.basicConfig(level="DEBUG")
logger = logging.getLogger()


class SOCKs5ProxyServer(StreamServer):
    _authenticate_client: Callable[[socket.socket], bool]
    auth: Optional[Tuple[str, str]]
    buff_size: int

    def __init__(self, addr: Tuple[str, int], auth: Optional[Tuple[str, str]] = None,
                 buff_size: int = 1024):
        super().__init__(addr, self.handle)
        self.buff_size = buff_size
        self.auth = auth
        if auth:
            server_print("Username/Password authentication configured.")
            server_print(f"{auth[0]}:{auth[1]}")
            self.acceptable_method = USERNAME_PASSWORD_METHOD
        else:
            server_print("No authentication method configured.")
            self.acceptable_method = NO_AUTH_METHOD
        # TODO: change the code around here, if you want other authentication methods
        self.accepted_method_message = PROTOCOL_VERSION + self.acceptable_method
        if self.acceptable_method == NO_AUTH_METHOD:
            self._authenticate_client = self._client_no_auth
        elif self.acceptable_method == USERNAME_PASSWORD_METHOD:
            self._authenticate_client = self._client_auth_username_password
        else:
            # TODO: here go your custom authentication methods you wanna use with your proxy server
            # TODO: that should be done by implementing the "_authenticate_client" callable (look it up in the code)
            raise NotImplementedError(f"Authentication method {self.acceptable_method} is not implemented.")

    def _client_no_auth(self, client: socket.socket) -> bool:
        # if no authentication for the server, just return
        return True

    def _client_auth_username_password(self, client: socket.socket) -> bool:
        subnegotiation_version = client.recv(1)
        if not subnegotiation_version:
            # client didn't send anything
            client.close()
            return False
        if subnegotiation_version != b'\x01':
            # client bad response
            client.sendall(USERNAME_PASSWORD_AUTH_FAILED)
            client.close()
            return False

        username_length = client.recv(1)
        if not username_length:
            client.close()
            return False
        username_length = username_length[0]  # now int
        if username_length < 1:
            client.sendall(USERNAME_PASSWORD_AUTH_FAILED)
            client.close()
            return False

        # recv username
        username = client.recv(username_length)
        if not username or len(username) != username_length:
            client.close()
            return False
        # here it doesn't matter, if we use UTF-8, ANSI or ASCII,
        # because for latin + alphanumeric + signs they are identical
        username = username.decode("utf-8")
        if username != self.auth[0]:
            client.sendall(USERNAME_PASSWORD_AUTH_FAILED)
            client.close()
            return False

        # recv password length
        password_length = client.recv(1)
        if not password_length:
            client.close()
            return False
        password_length = password_length[0]  # now int
        if password_length < 1:
            client.sendall(USERNAME_PASSWORD_AUTH_FAILED)
            client.close()
            return False

        # recv password
        password = client.recv(password_length)
        if not password or len(password) != password_length:
            client.close()
            return False
        password = password.decode("utf-8")
        if password != self.auth[1]:
            client.sendall(USERNAME_PASSWORD_AUTH_FAILED)
            client.close()
            return False

        # if it came through, the client is good
        client.sendall(USERNAME_PASSWORD_AUTH_SUCCESS)
        return True

    def _recv_handshake(self, client: socket.socket) -> bool:
        version = client.recv(1)
        if not version:
            client.close()
            return False
        if version != PROTOCOL_VERSION:
            client.sendall(HANDSHAKE_FAILURE_MESSAGE)
            client.close()
            return False

        nmethods = client.recv(1)
        if not nmethods:
            # no response
            client.close()
            return False
        nmethods = nmethods[0]  # converts byte to integer
        if nmethods < 1:
            # invalid nmethods length
            client.sendall(HANDSHAKE_FAILURE_MESSAGE)
            client.close()
            return False

        methods = client.recv(nmethods)
        if len(methods) != nmethods:
            # received wrong number of methods -> client misconfiguration or bad handshake
            client.sendall(HANDSHAKE_FAILURE_MESSAGE)
            client.close()
            return False
        if self.acceptable_method not in methods:
            # client doesn't support server's acceptable authentication method
            client.sendall(HANDSHAKE_FAILURE_MESSAGE)
            client.close()
            return False
        # server agrees with one of the authentication methods proposed by the client
        client.sendall(self.accepted_method_message)
        return True

    def _recv_request(self, client: socket.socket) -> Optional[socket.socket]:
        # receive protocol version
        version = client.recv(1)
        if not version or version != PROTOCOL_VERSION:
            reply = form_reply(CONNECTION_REFUSED_REPLY, IPv4_ADDRESS_TYPE, EMPTY_IPv4, PORT_0)
            client.sendall(reply)
            client.close()
            return None

        # receive command
        cmd = client.recv(1)
        if not cmd:
            # reply is empty, drop the connection
            client.close()
            return None
        if cmd != CONNECT_CMD:
            reply = form_reply(CMD_NOT_SUPPORTED_REPLY, IPv4_ADDRESS_TYPE, EMPTY_IPv4, PORT_0)
            client.sendall(reply)
            client.close()
            return None
        # TODO: the only supported cmd is CONNECT: no BIND or UDP (DIY and commit)

        # next byte must be 0 (reserved value)
        rsv = client.recv(1)
        if not rsv or rsv != RSV:
            # malformed client request
            reply = form_reply(CONNECTION_REFUSED_REPLY, IPv4_ADDRESS_TYPE, EMPTY_IPv4, PORT_0)
            client.sendall(reply)
            client.close()
            return None

        atyp = client.recv(1)
        if not atyp:
            # received no data
            client.close()
            return None
        if atyp == IPv4_ADDRESS_TYPE:
            # ipv4 has 4 octets (bytes)
            raw_address = client.recv(4)
            if not raw_address:  # no ip received
                client.close()
                return None
            if len(raw_address) != 4:
                # got ip address which consists of less than 4 bytes. WTF, client?
                reply = form_reply(CONNECTION_REFUSED_REPLY, IPv4_ADDRESS_TYPE, EMPTY_IPv4, PORT_0)
                client.sendall(reply)
                client.close()
                return None
            host = socket.inet_ntop(socket.AF_INET, raw_address)  # now it's a string
        elif atyp == IPv6_ADDRESS_TYPE:
            # ipv6 has 16 octets (bytes)
            raw_address = client.recv(16)
            if not raw_address:  # no ip received
                client.close()
                return None
            if len(raw_address) != 16:
                # got ip address which consists of less than 16 bytes
                reply = form_reply(CONNECTION_REFUSED_REPLY, IPv4_ADDRESS_TYPE, EMPTY_IPv4, PORT_0)
                client.sendall(reply)
                client.close()
                return None
            host = socket.inet_ntop(socket.AF_INET6, raw_address)  # now it's a string
        elif atyp == DOMAIN_NAME_ADDRESS_TYPE:
            domain_length = client.recv(1)
            if not domain_length:  # no data: dump the client
                client.close()
                return None
            raw_address = domain_length
            domain_length = domain_length[0]
            if domain_length < 1:
                # domain with 0 length? srsly?
                reply = form_reply(CONNECTION_REFUSED_REPLY, IPv4_ADDRESS_TYPE, EMPTY_IPv4, PORT_0)
                client.sendall(reply)
                client.close()
                return None
            # recv domain
            domain = client.recv(domain_length)
            if not domain or len(domain) < domain_length:
                client.close()
                return None
            raw_address += domain
            host = domain  # it's still bytes, but it doesn't matter
        else:
            # such address type is not supported
            reply = form_reply(ADDRESS_TYPE_NOT_SUPPORTED_REPLY, atyp, IPv4_ADDRESS_TYPE, PORT_0)
            client.sendall(reply)
            client.close()
            return None

        # now receive port
        raw_port = client.recv(2)
        if not raw_port or len(raw_port) != 2:
            client.close()
            return None
        # big endian
        port = int.from_bytes(raw_port, "big", signed=False)

        # now the proxy server should try to connect to the remote server
        try:
            # first off, fetch address info for SOCK_STREAM (TCP connection)
            # TODO: here, if UDP is ever implemented, you should change the target socket type
            addrinfos = socket.getaddrinfo(host, port,
                                           socket.AF_UNSPEC,  # we don't care what kind of ip address we get
                                           socket.SOCK_STREAM,  # it must be a TCP connection
                                           socket.IPPROTO_TCP,  # TCP
                                           socket.AI_ADDRCONFIG)  # dunno, just took it from Anorov
        except socket.gaierror:
            # unable to resolve the address
            reply = form_reply(SERVER_FAILURE_REPLY, atyp, raw_address, raw_port)
            client.sendall(reply)
            client.close()
            return None
        # now, the getaddrinfo function might have resolved to a couple of hosts
        # starting from the first one, the proxy server will try to connect to them
        dst = None
        family = None
        address = None
        for addrinfo in addrinfos:
            family, type, proto, _, address = addrinfo
            dst = socket.socket(family, type, proto)
            try:
                dst.connect(address)
                break  # the first one to connect is the winner
            except socket.error:
                dst.close()
                dst = None
                family = None
                address = None
        # only two valid address families: IPv4 and IPv6
        if family == socket.AF_INET:
            str_ip, int_port = address
            int_port = int(port)
            raw_ip = socket.inet_pton(socket.AF_INET, str_ip)
            raw_port = int_port.to_bytes(2, "big", signed=False)
            # server responds to the client, that it has successfully connected to the remote server,
            # using the IPv4 address
            reply = form_reply(SUCCEEDED_REPLY, IPv4_ADDRESS_TYPE, raw_ip, raw_port)
            client.sendall(reply)
            logger.debug(f"-> {str_ip}:{int_port}")
        elif family == socket.AF_INET6:
            # getaddrinfo returns a tuple of 4 elements for IPv6 addresses
            str_ip, int_port, _, _ = address
            int_port = int(port)
            raw_ip = socket.inet_pton(socket.AF_INET6, str_ip)
            raw_port = int_port.to_bytes(2, "big", signed=False)
            # server responds to the client, that it has successfully connected to the remote server,
            # using the IPv4 address
            reply = form_reply(SUCCEEDED_REPLY, IPv6_ADDRESS_TYPE, raw_ip, raw_port)
            client.sendall(reply)
            logger.debug(f"-> {str_ip}:{int_port}")
        else:
            # wasn't able to connect to any of the hosts
            reply = form_reply(HOST_UNREACHABLE_REPLY, atyp, raw_address, raw_port)
            client.sendall(reply)
            client.close()
            logger.debug(f"{raw_address}:{raw_port} is unreachable.")
        return dst  # return the destination socket, if such has been found

    def handle(self, src: socket.socket, addr: Tuple[str, int]) -> None:
        host, port = addr
        logger.debug(f"Connection from {host}:{port}.")
        handshake_result = self._recv_handshake(src)
        if not handshake_result:
            logger.debug("Handshake failure.")
            return  # bad handshake, the client is already closed
        auth_result = self._authenticate_client(src)
        if not auth_result:
            logger.debug("Authentication failure.")
            return  # bad authentication
        dst = self._recv_request(src)
        if dst is None:
            logger.debug("Connection to remote host failed.")
            return  # some error connecting to the destination server has occurred
        # now we're good. just exchange traffic between source and destination
        joinall([
            spawn(forward, src, dst),
            spawn(forward, dst, src)
        ])  # wait for the coroutines to finish data exchange
        # close the sockets
        src.close()
        dst.close()
        # proxy server DONE!


def print_help():
    print(f"\nSOCKs5 proxy server based on gevent greenlets. Supports username/password authentication."
          "\nSupported argument schemes:"
          "\n- <no arguments> -> opens server on 0.0.0.0:1080 (no auth)"
          "\n- <port>         -> opens server on 0.0.0.0:<port> (no auth)"
          "\n- <host> <port>  -> no auth on <host>:<port>"
          "\n- <host> <port> <username> <password>")


if __name__ == '__main__':
    import sys

    auth = None
    server_ip = "0.0.0.0"
    server_port = 1080

    args = sys.argv[1:]

    if not args:
        pass
    elif len(args) == 1:
        if args[0].lower() in {"-h", "--help"}:
            print_help()
            exit(0)
        else:
            server_port = args[0]
            try:
                server_port = int(server_port)
                assert 0 < server_port < 65536
            except ValueError:
                server_print(f"Unable to parse value to port number: {server_port}.")
                exit(1)
    elif len(args) == 2 or len(args) == 4:
        server_ip, server_port = args[0], args[1]
        try:
            server_port = int(server_port)
            assert 0 < server_port < 65536
        except ValueError:
            server_print(f"Unable to parse value to port number: {server_port}.")
            exit(1)
        except AssertionError:
            server_print(f"Port must be a value between 1 and 65535 inclusive.")
            exit(1)
        if len(args) == 4:
            username, password = args[2], args[3]
            auth = (username, password)
    else:
        server_print(f"Invalid number of arguments: {len(args)}.")
        print_help()
        exit(1)

    server = SOCKs5ProxyServer((server_ip, server_port), auth=auth)

    def stop_server():
        server_print("Stopping.")
        server.close()
        sys.exit(0)

    signal_handler(signal.SIGTERM, stop_server)
    signal_handler(signal.SIGINT, stop_server)
    server_print(f"Listening on {server_ip}:{server_port}")
    server.serve_forever()
