/** @file ftp_lib.h
 *
 * @brief FTP functions.
 *
 * @par
 * COPYRIGHT NOTICE: (c) 2022 U.S. Army. All rights reserved. This software is
 * placed in the public domain and may be used for any purpose, as long as that
 * purpose is in service of the United States Army. HOOAH! However, this notice
 * must not be changed or removed. No warranty is expressed or implied by the
 * publication or distribution of this source code.
 */

#ifndef FTP_lib_H
#define FTP_lib_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "net_lib.h"

enum Constraints
{
    MAX_MESSAGE_LENGTH = 2048,
    MAXE_FILE_SIZE     = 1016,

    ACCOUNT_REQUEST_DATA_MAX_LENGTH = 2036,
    DELETE_REQUEST_DATA_MAX_LENGTH  = 2041,
    LS_REQUEST_DATA_MAX_LENGTH      = 2036,
    LS_RESPONSE_DATA_MAX_LENGTH     = 2032,
    GET_REQUEST_DATA_MAX_LENGTH     = 2040,
    GET_RESPONSE_DATA_MAX_LENGTH    = 1016, // MAX FILE SIZE
    MKDIR_REQUEST_DATA_MAX_LENGTH   = 2036,
    PUT_REQUEST_DATA_MAX_LENGTH     = 2036,

    ACCOUNT_RESPONSE_MIN_LENGTH  = 6,
    LIST_DIR_RESPONSE_MIN_LENGTH = 16,
    GET_FILE_RESPONSE_MIN_LENGTH = 6
};

enum Op_Codes
{
    USER_OPERATOIN = 0x1,
    DELETE_FILE,
    LIST_DIR,
    GET_FILE,
    MAKE_DIR,
    PUT_FILE
};

enum Return_Codes
{
    SUCCESS = 0X1,
    SESSION_ERROR,
    PERMISSION_ERROR,
    USER_EXISTS,
    FILE_EXISTS,
    FAILURE = 0xff
};

enum User_Flags
{
    LOGIN,
    READ_ONLY,
    READ_WRITE,
    ADMIN,
    DELETE = 0xff
};

enum Overwrite_Flags
{
    NO_OVERWRITE,
    OVERWRITE
};

enum File_Type
{
    REG_FILE = 1,
    DIRECTORY
};

typedef struct __attribute__((__packed__)) Account_Request
{
    uint8_t  opcode;
    uint8_t  flag;
    uint16_t reserved;
    uint16_t name_len;
    uint16_t password_len;
    uint32_t session_id;
    char     p_credentials[ACCOUNT_REQUEST_DATA_MAX_LENGTH];
} Account_Request;

typedef struct __attribute__((__packed__)) Account_Response
{
    uint8_t  code;
    uint8_t  reserved;
    uint32_t session_id;
} Account_Response;

typedef struct __attribute__((__packed__)) Delete_File_Request
{
    uint8_t  opcode;
    uint8_t  reserved;
    uint8_t  filename_len;
    uint32_t session_id;
    char     p_file_name[DELETE_REQUEST_DATA_MAX_LENGTH];
} Delete_File_Request;

typedef struct __attribute__((__packed__)) List_Dir_Request
{
    uint8_t  opcode;
    uint8_t  reserved;
    uint16_t dir_name_len;
    uint32_t session_id;
    uint32_t current_pos;
    char     p_dir_name[LS_REQUEST_DATA_MAX_LENGTH];
} List_Dir_Request;

typedef struct __attribute__((__packed__)) List_Dir_Response
{
    uint8_t  code;
    uint8_t  reserved[3];
    uint32_t total_length;
    uint32_t length;
    uint32_t current_pos;
    char     p_ls_data[LS_RESPONSE_DATA_MAX_LENGTH];
} List_Dir_Response;

typedef struct __attribute__((__packed__)) Get_File_Request
{
    uint8_t  opcode;
    uint8_t  reserved;
    uint16_t filename_len;
    uint32_t session_id;
    char     p_file_name[GET_REQUEST_DATA_MAX_LENGTH];
} Get_File_Request;

typedef struct __attribute__((__packed__)) Get_File_Response
{
    uint8_t  code;
    uint8_t  reserved;
    uint32_t length;
    char     p_file_data[GET_RESPONSE_DATA_MAX_LENGTH];
} Get_File_Response;

typedef struct __attribute__((__packed__)) Make_Dir_Request
{
    uint8_t  opcode;
    uint8_t  reserved_one;
    uint16_t dir_name_len;
    uint32_t session_id;
    uint32_t reserved_two;
    char     p_dir_name[MKDIR_REQUEST_DATA_MAX_LENGTH];
} Make_Dir_Request;

typedef struct __attribute__((__packed__)) Put_File_Request
{
    uint8_t  opcode;
    uint8_t  flag;
    uint16_t filename_len;
    uint32_t session_id;
    uint32_t length;
    char     p_file_data[PUT_REQUEST_DATA_MAX_LENGTH];

} Put_File_Request;

int ftp_get_command(FTP_ctx *p_ftp_ctx, FTP_Message *p_response);

int user_operation(FTP_ctx *p_ftp_ctx, Account_Response *p_response);

int make_directory(FTP_ctx *p_ftp_ctx, FTP_Message *p_response);

int delete_file(FTP_ctx *p_ftp_ctx, FTP_Message *p_response);

int put_file(FTP_ctx *p_ftp_ctx, FTP_Message *p_response);

int get_file(FTP_ctx *p_ftp_ctx, Get_File_Response *p_response);

int read_file(Get_File_Response *p_response, FILE *ph_file);

int list_dir(FTP_ctx *p_ftp_ctx, List_Dir_Response *p_response);

int write_dir(FTP_ctx           *p_ftp_ctx,
              List_Dir_Response *p_response,
              char              *p_buf,
              ssize_t            buf_len);

int validate_path(char *p_server_dir, char *p_path, bool b_is_file);

uint32_t generate_session_id(Account_Request *p_account);

#endif /* FTP_LIB_H */

/*** end of file ***/