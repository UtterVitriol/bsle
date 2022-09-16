"""A class to interact with the capstone FTP server.

Provides an interface with a remote FTP server.
"""

import socket
import os
import struct

import ftp_headers


class FTPClientError(Exception):
    """Base FTPClient Exception"""
    pass


class PermissionInvalidError(FTPClientError):
    """Permission invalid exception.

    When user_create permissions are invalid.
    """
    pass


class InvalidCredentialFormatError(FTPClientError):
    """Invalid credentials exception.

    When username and password don't follow format described below.

    Attributes:
        message: Default error message.
    """

    def __init__(self, message=None):
        """Inits InvalidCredentialFormatError with default message."""
        if message is None:
            self.message = ('Username and password must be alphanumerical'
                            ' [a-zA-Z0-9] and at least one (1) character long')
        else:
            self.message = message
        super().__init__(self.message)


class ServerError(FTPClientError):
    """Base Server error exception"""
    pass


class ServerSessionTimeoutError(ServerError):
    """Server session timeout exception.

    Raised when server sends session error.

    Attributes:
        message: Default error message.
    """

    def __init__(self):
        """Inits ServerSessionTimeoutError with default message."""
        self.message = ('Session timed out')
        super().__init__(self.message)


class ServerCriticalError(ServerError):
    """Server critical error exception.

    Raised when server sends unexpected data.
    """

    def __init__(self):
        """Inits ServerCriticalError with default message."""
        self.message = ('Server malfunction')
        super().__init__(self.message)

    pass


class ServerFullError(ServerError):
    """Server full exception.

    Raised when RST is received and I think the server is full.
    """

    def __init__(self):
        """Inits ServerFullError with default message."""
        self.message = ('Server is full')
        super().__init__(self.message)

    pass


class ServerClosedError(ServerError):
    """Server closed exception.

    Raised when send or recv fails.
    """

    def __init__(self):
        """Inits ServerClosedError with default message."""
        self.message = ('Server shut down')
        super().__init__(self.message)

    pass


class FTPClient:
    """Connect to and interact with FTP server

    Attributes:
        header_handler: Converts ftp protocol from bytes to header dataclasses
                        and vice versa.
        session_id: Used to authenticate with the remote FTP server.
        _max_buf: Miximum message size.
        _max_file_size: Maximum file size.
        commands_help: Dictionary of commands and their descriptions.
        commands: Dictionary of commands and their functions.
        server_addr: IP and port of remote FTP server.
    """

    def __init__(self, ip, port):
        """Inits FTPClient with connected socket, initialized HeaderHandler.."""
        self.connect(ip, port)
        self.header_handler = ftp_headers.HeaderHandler()
        self.session_id = 0

        self._max_buf = 2048
        self._max_file_size = 1016

        self.commands_help = {
            'CREATE_USER':
            ('create_user [username] [password] [permissions]:\n\t\t\t\tcreates'
             ' user with username [username], password [password] and'
             ' permissions [permissions] (READ_ONLY, READ_WRITE or ADMIN)'),
            'HELP':
            ('help [optional command]:\tprints available commands, optionally'
             ' describes given [command]'),
            'DELETE_USER':
            'delete_user [username]:\n\t\t\t\tdeletes user',
            'L_LS':
            'l_ls [optional path]:\t\tlists local directory contents',
            'LS':
            'ls [optional path]:\t\tlists remote directory contents',
            'L_DELETE':
            "l_delete [path]:\t\tdeletes file at local [path]",
            'GET':
            ('get [src] [dst]:\t\tgets a file from server [src] path and copies'
             ' it to the client [dst] path'),
            'PUT':
            ('put [src] [dst] [optional OVERWRITE]:\t\tsends a file from client'
             ' [src] path to be. adding \'OVERWRITE\' will cause files'
             ' to be overwritten'
             ' placed in server [dst] path'),
            'L_MKDIR':
            'l_mkdir [path]:\t\t\tmakes directory at client [path]',
            'DELETE':
            'delete [path]:\t\t\tdeletes file at server [path]',
            'MKDIR':
            'mkdir [path]:\t\t\tmakes directory at server [path]',
            'QUIT/EXIT':
            'quit:\t\t\t\texits program'
        }

        self.commands = {
            'CREATE_USER': self.user_operation,
            'DELETE_USER': self.user_operation,
            'GET': self.get_file,
            'PUT': self.put_file,
            'DELETE': self.delete_file,
            'L_DELETE': self.local_delete_file,
            'LS': self.list_dir,
            'L_LS': self.local_list_dir,
            'MKDIR': self.make_dir,
            'L_MKDIR': self.local_make_dir
        }

    def __enter__(self):
        return self

    def __exit__(self, exc_typ, ecx_value, traceback):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            # not connected
            pass
        self.sock.close()

    def connect(self, ip, port):
        """Connect to remote FTP server.

        Attempts to connect to remote FTP server at ip on port. Times out after
        10 seconds.

        Args:
            ip: Remote FTP server IP address.
            port: Remote FTP server port number.

        Returns:
            Nothing.

        Raises:
            FTPClientError: An error occurred initializing socket. Or ip address
                            is invalid. Or port number is invalid. Or connection
                            was refused.

        """
        self.server_addr = (ip, port)

        try:
            self.sock = socket.socket()
        except socket.error as e:
            raise FTPClientError(e)

        try:
            self.sock.settimeout(10)
            self.sock.connect(self.server_addr)
            self.sock.settimeout(None)
        except socket.gaierror:
            raise FTPClientError("Invalid IP address")
        except OverflowError:
            raise FTPClientError("Port must be 0-65535")
        except ConnectionRefusedError:
            raise FTPClientError("Connection refused")

    def interactive(self):
        """Provides an interactive shell.

        Provides an interactive shell that can send commands from the user
        continuously while client session is valid.

        Args:
            None.

        Returns:
            Nothing.

        Raises:
            ServerError: An error occurred communicating with the server.
            FTPClientError: An error occurred trying to perform command.
        """

        help_list = list(self.commands_help.values())

        while True:

            try:
                input_str = input(">").split(" ")
            except (EOFError, KeyboardInterrupt):
                break

            command = input_str[0].upper()

            if command in ("QUIT", "EXIT"):
                break

            elif command == "HELP":
                if len(input_str) == 2:
                    if input_str[1].upper() in self.commands_help:
                        print(self.commands_help[input_str[1].upper()])
                        continue
                print(*help_list, sep='\n')

            elif command in self.commands:
                function = self.commands[command]

                try:
                    if command == "DELETE_USER":
                        if len(input_str) > 2:
                            print(self.commands_help[command])
                            continue
                        function(input_str[1], action="DELETE")

                    elif command == "PUT" and len(input_str) == 4:
                        if input_str[3].upper() == "OVERWRITE":
                            function(*input_str[1:3], True)
                        else:
                            print(self.commands_help[command])
                            continue
                    else:
                        function(*input_str[1:])

                except (IndexError, TypeError):
                    print(self.commands_help[command])
                except ServerError as e:
                    print(e)
                    return
                except FTPClientError as e:
                    print(e)

            else:
                print(f"Error: invalid command '{command}'\n")
                print(*help_list, sep='\n')

    def user_operation(self,
                       username,
                       password=False,
                       action="LOGIN",
                       silent=False):
        """User Operations.

        Creates and sends user operation requests. Receives and decodes user
        operation responses.

        Args:
            username: Account username.
            password: Account password.
            action: User operation to be performed.
            silent: Print response code string or not.

        Returns:
            Nothing.

        Raises:
            InvalidCredentialFormatError: Credential format is invalid.
            PermissionInvalidError: Action provided is invalid.
            ServerClosedError: Server Connection ended.
            ServerFullError: The server is full.
            ServerSessionTimeoutError: Session timed out.
            ServerCriticalError: Server sent bad data.
        """

        action = action.upper()

        if not username.isalnum() or len(username) < 1:
            raise InvalidCredentialFormatError()

        if password:
            if not password.isalnum() or len(password) < 1:
                raise InvalidCredentialFormatError()

        if action == "DELETE":
            password = ''

        if (len(username) + len(password)) > 2032:
            raise InvalidCredentialFormatError('Username + password is too'
                                               ' long (2032 characters max)')

        username = username.lower()

        try:
            header = ftp_headers.AccountRequest(
                self.header_handler.op_codes["USER_OPERATION"],
                self.header_handler.user_flagss[action], 0, len(username),
                len(password), self.session_id,
                bytearray("".join((username, password)), 'utf-8'))
        except KeyError as e:
            raise PermissionInvalidError("".join(
                ("Invalid Permission: ", *e.args)))

        request = self.header_handler.to_bytes(header)

        self._send_data(request)

        try:
            response_data = self._recv_data(6)
        except ServerClosedError as e:
            if action == "LOGIN":
                raise ServerFullError()
            else:
                raise e

        response = self._convert_response(response_data, header.opcode)

        code = self.header_handler.return_codes.get(response.code)

        if code == "SUCCESS":
            if not silent:
                print(code)
            self.session_id = response.session_id
        elif code == "SESSION_ERROR":
            raise ServerSessionTimeoutError()
        else:
            if code is None:
                raise ServerCriticalError()
            raise FTPClientError(
                self.header_handler.return_codes[response.code])

    def delete_file(self, filename):
        """Delete Server File.

        Delete file from FTP server.

        Args:
            filename: Name of file to be deleted.

        Returns:
            Nothing.

        Raises:
            ServerCriticalError: Server sent bad data.
            ServerSessionTimeoutError: Session timed out.
        """

        # use one less than actual max, incase I need to add a '.'
        if len(filename) > 2040:
            raise FTPClientError("Filename is too long (2040 characters max)")

        if filename[0] == '/':
            filename = "".join(('.', filename))

        header = ftp_headers.DeleteFileRequest(
            self.header_handler.op_codes["DELETE_FILE"], 0, len(filename),
            self.session_id, bytearray(filename, 'utf-8'))

        request = self.header_handler.to_bytes(header)

        self._send_data(request)

        response_data = self._recv_data(1)

        response = self._convert_response(response_data, header.opcode)

        code = self.header_handler.return_codes.get(response.code)

        if code is None:
            raise ServerCriticalError()
        elif code == "SESSION_ERROR":
            raise ServerSessionTimeoutError()
        else:
            print(code)

    def local_delete_file(self, filename):
        """Delete Local File

        Delete local file.

        Args:
            filename: Name of file to be deleted.

        Returns:
            Nothing.

        Raises:
            FTPClientError: File is not found, is a directory or other error.
        """
        try:
            os.remove(filename)
        except FileNotFoundError:
            raise FTPClientError(f"File '{filename}' does not exist")
        except IsADirectoryError:
            raise FTPClientError(f"File '{filename}' is a directory")
        except OSError as e:
            raise FTPClientError(e)

    def list_dir(self, directory='/'):
        """List Server Directory

        List contents of server directory.

        Args:
            directory: Directory to list contents from.

        Returns:
            Nothing.

        Raises:
            FTPClientError: Directory name is too long or response code isn't
                            success.
            ServerCriticalError: Server send bad data.
            ServersessionTimeoutError: Session timed out.
        """

        # use one less than actual max, incase I need to add a '.'
        if len(directory) > 2035:
            raise FTPClientError(
                "Directory name too long (2035 characters max")

        # add '.' to directory path if it isn't present
        # easier to do it here than on the server
        if directory[0] == '/':
            directory = "".join(('.', directory))

        header = ftp_headers.ListDirRequest(
            self.header_handler.op_codes["LIST_DIR"], 0, len(directory),
            self.session_id, 0, bytearray(directory, 'utf-8'))

        request = self.header_handler.to_bytes(header)

        self._send_data(request)

        dir_data = b''

        while True:
            response_data = self._recv_data(self._max_buf)

            response = self._convert_response(response_data, header.opcode)

            code = self.header_handler.return_codes.get(response.code)

            if code != "SUCCESS":
                if code is None:
                    raise ServerCriticalError()
                elif code == "SESSION_ERROR":
                    raise ServerSessionTimeoutError()
                else:
                    raise FTPClientError(code)

            header.current_pos += response.length

            dir_data = b''.join((dir_data, response.dir_data))

            if header.current_pos == response.total_length:
                break

            # request more data
            request = self.header_handler.to_bytes(header)

            self._send_data(request)

        # list directory
        for item in dir_data.split(b'\00')[:-1]:
            item = item.decode()
            if item[0] == '1':
                print(f"File - \'{item[1:]}\'")
            elif item[0] == '2':
                print(f"Directory - \'{item[1:]}\'")

    def local_list_dir(self, directory='./'):
        """List Local Directory

        List contents of local directory.

        Args:
            directory: Directory to list contents from.

        Returns:
            Nothing.

        Raises:
            FTPClientError: Directory is not a directory or os method failed.
        """
        try:
            dir_items = os.listdir(directory)
            for item in dir_items:
                with_sep = "".join(
                    (directory, os.sep if os.sep not in directory else '',
                     item))
                if os.path.isfile(with_sep):
                    print(f"File - \'{item}\'")
                elif os.path.isdir(with_sep):
                    print(f"Directory - \'{item}\'")
                else:
                    print(f"Other - \'{item}\'")
        except NotADirectoryError as e:
            raise FTPClientError(f"'{directory}' is not a directory")
        except OSError as e:
            raise FTPClientError(e)

    def get_file(self, source, destination):
        """Get File

        Retreive file from server.

        Args:
            source: File to get.
            destination: Where to put it.

        Returns:
            Nothing.

        Raises:
            FTPClientError: Destination is too long.
            ServerCriticalError: Server sent bad data.
            ServerSessionTimeoutError: Session timed out.
        """

        # use one less than actual max, incase I need to add a '.'
        if len(destination) > 2039:
            raise FTPClientError(
                "Destination path too long (2039 characters max")

        if source[0] == '/':
            source = "".join(('.', source))

        header = ftp_headers.GetFileRequest(
            self.header_handler.op_codes["GET_FILE"], 0, len(source),
            self.session_id, bytearray(source, 'utf-8'))

        request = self.header_handler.to_bytes(header)

        self._send_data(request)

        response_data = self._recv_data(self._max_buf)

        response = self._convert_response(response_data, header.opcode)

        code = self.header_handler.return_codes.get(response.code)

        if code != 'SUCCESS':
            if code is None:
                raise ServerCriticalError()
            elif code == "SESSION_ERROR":
                raise ServerSessionTimeoutError()
            else:
                raise FTPClientError(code)

        with open(f"{destination}", 'wb') as f:
            f.write(response.file_data)

        print(code)

    def make_dir(self, directory):
        """Make Server Directory.

        Create directory on server.

        Args:
            directory: Directory to be created.

        Returns:
            Nothing.

        Raises:
            FTPClientError: Directoury too long.
            ServerCriticalError: Server sent bad data.
            ServerSessionTimeoutError: Session timed out.
        """

        # use one less than actual max, incase I need to add a '.'
        if len(directory) > 2035:
            raise FTPClientError(
                "Directory name too long (2035 characters max")

        if directory[0] == '/':
            directory = "".join(('.', directory))

        header = ftp_headers.MakeDirRequest(
            self.header_handler.op_codes["MAKE_DIR"], 0, len(directory),
            self.session_id, 0, bytearray(directory, 'utf-8'))

        request = self.header_handler.to_bytes(header)

        self._send_data(request)

        response_data = self._recv_data(1)

        response = self._convert_response(response_data, header.opcode)

        code = self.header_handler.return_codes.get(response.code)

        if code is None:
            raise ServerCriticalError()
        elif code == "SESSION_ERROR":
            raise ServerSessionTimeoutError()
        else:
            print(code)

    def local_make_dir(self, directory):
        """Make Local Directory.

        Create local directory.

        Args:
            directory: Directory to be created.

        Returns:
            Nothing.

        Raises:
            FTPClientError: Directory already exists or oserror.
        """
        try:
            os.mkdir(directory)
        except FileExistsError:
            raise FTPClientError(f"'{directory}' already exists")
        except OSError as e:
            raise FTPClientError(e)

    def put_file(self, source, destination, overwrite=False):
        """Put File

        Send local file to server.

        Args:
            source: File to send.
            destination: Destination on server.
            overwrite: Overwrites file on server if True.

        Returns:
            Nothing.

        Raises:
            FTPClientError: Destintation is too long.
            FTPClientError: Source not found.
            FTPClientError: Source file is too large.
            FTPClientError: OSError.
            ServerCriticalError: Server sent bad data.
            ServerSesssionTimeoutError: Session timed out.
        """

        try:
            if os.path.isdir(source):
                raise FTPClientError(f"{source} is a directory...")
        except OSError as e:
            raise FTPClientError(e)

        # this max leaves room for max file size
        # use one less than actual max, incase I need to add a '.'
        if len(destination) > 1027:
            raise FTPClientError("Destination too long (1027 characters max)")
        if destination[0] == '/':
            destination = "".join(('.', destination))

        try:
            file = open(source, "rb")
        except FileNotFoundError:
            raise FTPClientError(f"Error: file '{source}' does not exist")
        except OSError as e:
            raise FTPClientError(e)

        try:
            file_sz = os.path.getsize(source)
        except OSError as e:
            raise FTPClientError(e)

        if file_sz > self._max_file_size:
            file.close()
            raise FTPClientError(
                f"Error: file {source} is too large (> 1016 bytes)")

        max_length = (self._max_buf -
                      ftp_headers.PutFileRequest.variable_data_offset)

        if (len(destination) + file_sz) > max_length:
            file.close()
            raise FTPClientError(f"Error: file {destination} is too large...")

        try:
            file_data = file.read(1016)
        except OSError as e:
            file.close()
            raise FTPClientError(e)
        file.close()

        header = ftp_headers.PutFileRequest(
            self.header_handler.op_codes["PUT_FILE"], overwrite,
            len(destination), self.session_id, file_sz, b"".join(
                (bytes(destination, 'utf-8'), file_data)))

        request = self.header_handler.to_bytes(header)

        # send put request
        self._send_data(request)

        response_data = self._recv_data(1)

        response = self._convert_response(response_data, header.opcode)

        code = self.header_handler.return_codes.get(response.code)

        if code != 'SUCCESS':
            if code is None:
                raise ServerCriticalError()
            elif code == "SESSION_ERROR":
                raise ServerSessionTimeoutError()
            else:
                raise FTPClientError(code)

        print(code)

    def _send_data(self, data):
        """Send data.

        Send data to sever.

        Args:
            data: data to send.

        Returns:
            Nothing.

        Raises:
            ServerClosedError: Server connection closed.
        """
        try:
            self.sock.send(data)
        except OSError:
            raise ServerClosedError()

    def _recv_data(self, size):
        """Receive data.

        Receive data from server.

        Args:
            size: Size of data to receive.

        Returns:
            Nothing.

        Raises:
            ServerClosedError: Server connection closed.
        """

        try:
            data = self.sock.recv(size)
        except ConnectionResetError:
            raise ServerClosedError()

        if len(data) == 0:
            raise ServerClosedError()

        return data

    def _convert_response(self, response_data, opcode):
        """Convert resposne.

        Convert server response bytes to dataclass.

        Args:
            response_data: Data from server.
            opcode: Used to determine which data class to create.

        Returns:
            response: Initialized dataclass of response.

        Raises:
            ServerCriticalError: Server sent bad data.
        """
        try:
            response = self.header_handler.from_bytes(response_data, opcode)
        except (struct.error, KeyError):
            raise ServerCriticalError()

        return response
