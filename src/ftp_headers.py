"""Provides dataclasses to create FTP requests and responses.

Outlines FTP head formats and converts request dataclasses to bytes and response
bytes to dataclasses.
"""

import dataclasses
import struct


@dataclasses.dataclass
class AccountRequest:
    """User Operation Request.

    Used to login, create or delete users to/from server.

    Attributes:
        opcode: Should always be 1.
        flag: Type of user operation.
        reserved: Reserved.
        name_len: Length of username string.
        password_len: Length of password string.
        session_id: Used to authenticate with server.
        credentials: Username and password as one string.
        variable_data_offset: Byte offset to credentials.
        format_string: String representing dataclass as bytearray for struct.
    """

    opcode: int
    flag: int
    reserved: int
    name_len: int
    password_len: int
    session_id: int
    credentials: str

    variable_data_offset = 12
    format_string = "!BBHHHI{}s"

    def __post_init__(self):
        """Inits AccountRequest with length of credentials in format string."""
        self.format_string = AccountRequest.format_string.format(
            len(self.credentials))


@dataclasses.dataclass
class AccountResponse:
    """User Operation Response.

    Response of previous request from server.

    Attributes:
        code: That return status of the previous request.
        reserved: Reserved.
        session_id: Used to authenticate with server. Is populated when a
                    successful login request happens.
        variable_data_offset: Unused here.
        format_string: String representing dataclass as bytearray for struct.
    """

    code: int
    reserved: int
    session_id: int

    variable_data_offset = 0
    format_string = "!BBI"


@dataclasses.dataclass
class DeleteFileRequest:
    """Delete File Request.

    Request to delete file from server.

    Attributes:
        opcode: Should always be 2.
        reserved: Reserved.
        filename_len: Length of filename string.
        sesssion_id: Used to authenticate with server.
        filename: File name to delete.
        variable_data_offset: Byte offset to filename.
        format_string: String representing dataclass as bytearray for struct.
    """

    opcode: int
    reserved: int
    filename_len: int
    session_id: int
    filename: str

    variable_data_offset = 7
    format_string = "!BBBI{}s"

    def __post_init__(self):
        """Inits DeleteFileRequest with length of
           filename in format string.
        """
        self.format_string = DeleteFileRequest.format_string.format(
            len(self.filename))


@dataclasses.dataclass
class GenericResponse:
    """Single byte responses.

    Used for all other responses that only require one byte.

    Attributes:
        code: That return status of the previous request.
        variable_data_offset: Unused here.
        format_string: String representing dataclass as bytearray for struct.
    """

    code: int

    variable_data_offset = 0
    format_string = "!B"


@dataclasses.dataclass
class ListDirRequest:
    """List Directory Request.

    Request to list directory contest of server.

    Attributes:
        opcode: should always be 3.
        reserved: Reserved.
        dir_name_len: Length of directory name string.
        session_id: Used to authenticate with server.
        current_pos: Position of the server in the server buffer of directory
                     data.
        dir_name: Name of directory.
        variable_data_offset: Byte offset to dir_name.
        format_string: String representing dataclass as bytearray for struct.
    """

    opcode: int
    reserved: int
    dir_name_len: int
    session_id: int
    current_pos: int
    dir_name: str

    variable_data_offset = 12
    format_string = "!BBHII{}s"

    def __post_init__(self):
        """Inits ListDirRequest with length of dir_name in format string."""
        self.format_string = ListDirRequest.format_string.format(
            len(self.dir_name))


@dataclasses.dataclass
class ListDirResponse:
    """List Directory Response.

    Response of previous request from server.

    Attributes:
        code: That return status of the previous request.
        reserved: Reserved.
        total_length: Total length of server buffer that contains directory data
        current_pos: Current position of the server in the server buffer of
                     directory data.
        dir_data: Directory data as string.
        variable_data_offset: Byte offset to dir_data.
        format_string: String representing dataclass as bytearray for struct.
    """

    code: int
    reserved: str
    total_length: int
    length: int
    current_pos: int
    dir_data: str

    variable_data_offset = 16
    format_string = "!B3sIII{}s"


@dataclasses.dataclass
class GetFileRequest:
    """Get File Request.

    Request to get a file from the server

    Attributes:
        opcode: Should always be 4.
        reserved: Reserved.
        filename_len: Length of filename string.
        session_id: Used to authenticate with server.
        filename: Name of file to get from server.
        variable_data_offset: Byte offset to filename.
        format_string: String representing dataclass as bytearray for struct.

    """

    opcode: int
    reserved: int
    filename_len: int
    session_id: int
    filename: str

    variable_data_offest = 8
    format_string = "!BBHI{}s"

    def __post_init__(self):
        """Inits GetFileRequest with length of filename in format string."""
        self.format_string = GetFileRequest.format_string.format(
            len(self.filename))


@dataclasses.dataclass
class GetFileResponse:
    """Get File Response.

    Response of previous request from server.

    Attributes:
        code: That return status of the previous request.
        reserved: Reserved.
        length: Lenght of file_data.
        file_data: Data of file requested.
        variable_data_offset: Byte offset to file_data.
        format_string: String representing dataclass as bytearray for struct.
    """

    code: int
    reserved: int
    length: int
    file_data: str

    variable_data_offset = 6
    format_string = "!BBI{}s"


@dataclasses.dataclass
class MakeDirRequest:
    """Make Directory Request.

    Request to make directory on server.

    Attributes:
        opcode: Should always be 5.
        reserved_one: Reserved.
        dir_name_len: Length of directory name.
        reserved_two: Reserved.
        dir_name: Directory name.
        variable_data_offset: Byte offset to dir_name.
        format_string: String representing dataclass as bytearray for struct.
    """

    opcode: int
    reserved_one: int
    dir_name_len: int
    session_id: int
    reserved_two: int
    dir_name: str

    variable_data_offset = 12
    format_string = "!BBHII{}s"

    def __post_init__(self):
        """Inits MakeDirRequest with length of dir_name in format string."""
        self.format_string = MakeDirRequest.format_string.format(
            len(self.dir_name))


@dataclasses.dataclass
class PutFileRequest:
    """"Put File Request.

    Request to put file on server.

    Attributes:
        opcode: Should always be 6.
        flag: 1 To overwrite existing file or 0 to not.
        filename_len: Length of file name.
        session_id: Used to authenticate with server.
        length: Length of file data.
        file_data: File data to send to server.
        variable_data_offset: Byte offset to file_data.
        format_string: String representing dataclass as bytearray for struct.
    """

    opcode: int
    flag: int
    filename_len: int
    session_id: int
    length: int
    file_data: str

    variable_data_offset = 12
    format_string = "!BBHII{}s"

    def __post_init__(self):
        """Inits PutFileRequest with length of file_data in format string."""
        self.format_string = PutFileRequest.format_string.format(
            len(self.file_data))


class HeaderHandler:
    """Converts header dataclasses to byte arrays and vice versa.

    Attributes:
        op_codes: Dictionary of op codes and their string representation.
        return_codes: Dictionary of return codes and their string representation
        user_flags: Dictionary of user flags and their string representation.
        request_headers: Dictionary of op codes and their associated dataclass.
        reaponse_headers: Dictionary of return codes and their associated
                          dataclass.
        overwrite_flags: Dictionary of overwrite flag strings and their integer
                         representation.
        file_type_flags: Dictionary of file type flags and their integer
                         representation.
    """

    def __init__(self):

        self.op_codes = {
            "USER_OPERATION": 1,
            "DELETE_FILE": 2,
            "LIST_DIR": 3,
            "GET_FILE": 4,
            "MAKE_DIR": 5,
            "PUT_FILE": 6
        }

        self.return_codes = {
            1: "SUCCESS",
            2: "SESSION_ERROR",
            3: "PERMISSION_ERROR",
            4: "USER_EXISTS",
            5: "FILE_EXISTS",
            255: "FAILURE"
        }

        self.user_flagss = {
            "LOGIN": 0,
            "READ_ONLY": 1,
            "READ_WRITE": 2,
            "ADMIN": 3,
            "DELETE": 255
        }

        self.request_headers = {
            1: AccountRequest,
            2: DeleteFileRequest,
            3: ListDirRequest,
            4: GetFileRequest,
            5: MakeDirRequest,
            6: PutFileRequest
        }

        self.response_headers = {
            1: AccountResponse,
            2: GenericResponse,
            3: ListDirResponse,
            4: GetFileResponse,
            5: GenericResponse,
            6: GenericResponse
        }

        self.overwrite_flags = {"NO_OVERWRITE": 0, "OVERWRITE": 1}
        self.file_type_flags = {"REG_FILE": 1, "DIRECTORY": 2}

    def to_bytes(self, header):
        """Converts header dataclass to header bytes.

        Args:
            header: Dataclass to be converted to bytes.

        Returns:
            Header as bytes.
        """
        return struct.pack(header.format_string,
                           *list(dataclasses.asdict(header).values()))

    def from_bytes(self, buf, response_header=None):
        """Converts header bytes into header dataclass

        Args:
            buf: Header bytes to be converted.
            resposne_header: Response header to be converted to.
        """
        if response_header:
            header_type = self.response_headers[response_header]

        else:
            header_type = self.request_headers[buf[0]]

        header = header_type(*struct.unpack(
            header_type.format_string.format(
                len(buf) - header_type.variable_data_offset), buf))

        return header
