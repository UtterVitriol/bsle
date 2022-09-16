/** @file ftp_lib.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/errno.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>

#include "ftp_lib.h"
#include "net_lib.h"
#include "accounts.h"

/**
 * @brief Determines ftp commmand and calls appropriate function.
 *
 * @param p_client Client (stores request).
 * @param p_response Response to send.
 *
 * @return Length of resonse on success, otherwise -1.
 */
int
ftp_get_command(FTP_ctx *p_client, FTP_Message *p_response)
{

    if (!p_client || !p_response)
    {
        fprintf(stderr, "Serv_loop Error: NULL ptr\n");

        return -1;
    }

    int command      = -1;
    int response_len = 1;

    command = p_client->message.opcode;

    switch (command)
    {
        case (USER_OPERATOIN):

            response_len
                = user_operation(p_client, (Account_Response *)p_response);

            break;

        case (DELETE_FILE):

            if ((READ_WRITE == p_client->auth_level)
                || (ADMIN == p_client->auth_level))
            {
                response_len = delete_file(p_client, p_response);
            }
            else
            {
                p_response->opcode = PERMISSION_ERROR;
            }

            break;

        case (LIST_DIR):

            // Any valid authentication level.
            //
            if ((p_client->auth_level >= READ_ONLY)
                && (p_client->auth_level <= ADMIN))
            {
                response_len
                    = list_dir(p_client, (List_Dir_Response *)p_response);
            }
            else
            {
                p_response->opcode = PERMISSION_ERROR;
                response_len       = LIST_DIR_RESPONSE_MIN_LENGTH;
            }

            break;

        case (GET_FILE):

            // Any valid authentication level.
            //
            if ((p_client->auth_level >= READ_ONLY)
                && (p_client->auth_level <= ADMIN))
            {
                response_len
                    = get_file(p_client, (Get_File_Response *)p_response);
            }
            else
            {
                p_response->opcode = PERMISSION_ERROR;
                response_len       = GET_FILE_RESPONSE_MIN_LENGTH;
            }

            break;

        case (MAKE_DIR):

            if ((READ_WRITE == p_client->auth_level)
                || (ADMIN == p_client->auth_level))
            {
                response_len = make_directory(p_client, p_response);
            }
            else
            {
                p_response->opcode = PERMISSION_ERROR;
            }

            break;

        case (PUT_FILE):

            if ((READ_WRITE == p_client->auth_level)
                || (ADMIN == p_client->auth_level))
            {
                response_len = put_file(p_client, p_response);
            }
            else
            {
                p_response->opcode = PERMISSION_ERROR;
            }

            break;

        default:

            p_response->opcode = FAILURE;

            break;
    }

    return response_len;
}

/**
 * @brief Login, create user or delete user.
 *
 * @param p_client Client (stores request).
 * @param p_response Response to send.
 *
 * @return Length of response.
 */
int
user_operation(FTP_ctx *p_client, Account_Response *p_response)
{
    if (!p_client)
    {
        fprintf(stderr, "User_operation Error: NULL ptr\n");
        return -1;
    }

    int ret = -1;

    Account_Request *p_request = (Account_Request *)&p_client->message;

    p_request->name_len     = ntohs(p_request->name_len);
    p_request->password_len = ntohs(p_request->password_len);
    p_request->session_id   = ntohl(p_request->session_id);

    if (p_request->flag != LOGIN)
    {
        if (p_request->session_id != p_client->session_id)
        {
            p_response->code = SESSION_ERROR;
            goto END;
        }
    }

    switch (p_request->flag)
    {
        case (LOGIN):

            ret = client_login(p_request, p_client->p_server_ctx->p_accounts);
            if (ret > 0)
            {
                p_client->auth_level = ret;
                p_response->code     = SUCCESS;
                p_client->session_id = htonl(generate_session_id(p_request));
            }
            else
            {
                p_response->code = FAILURE;
            }

            break;

        case (READ_ONLY):

            if ((p_client->auth_level >= READ_ONLY)
                && (p_client->auth_level <= ADMIN))
            {
                ret = add_account(p_request,
                                  p_client->p_server_ctx->p_accounts);
                if (0 == ret)
                {
                    p_response->code = SUCCESS;
                }
                else if (1 == ret)
                {
                    p_response->code = USER_EXISTS;
                }
                else
                {
                    p_response->code = FAILURE;
                }
            }
            else
            {
                p_response->code = PERMISSION_ERROR;
            }

            break;

        case (READ_WRITE):

            if ((READ_WRITE == p_client->auth_level)
                || (ADMIN == p_client->auth_level))
            {
                ret = add_account(p_request,
                                  p_client->p_server_ctx->p_accounts);
                if (0 == ret)
                {
                    p_response->code = SUCCESS;
                }
                else if (1 == ret)
                {
                    p_response->code = USER_EXISTS;
                }
                else
                {
                    p_response->code = FAILURE;
                }
            }
            else
            {
                p_response->code = PERMISSION_ERROR;
            }

            break;

        case (ADMIN):

            if (ADMIN == p_client->auth_level)
            {
                ret = add_account(p_request,
                                  p_client->p_server_ctx->p_accounts);
                if (0 == ret)
                {
                    p_response->code = SUCCESS;
                }
                else if (1 == ret)
                {
                    p_response->code = USER_EXISTS;
                }
                else
                {
                    p_response->code = FAILURE;
                }
            }
            else
            {
                p_response->code = PERMISSION_ERROR;
            }

            break;

        case (DELETE):

            if (ADMIN == p_client->auth_level)
            {
                ret = delete_account(p_request,
                                     p_client->p_server_ctx->p_accounts);
                if (1 == ret)
                {
                    p_response->code = SUCCESS;
                }
                else
                {
                    p_response->code = FAILURE;
                }
            }
            else
            {
                p_response->code = PERMISSION_ERROR;
            }

            break;

        default:

            p_response->code = FAILURE;

            break;
    }

END:
    p_response->session_id = htonl(p_client->session_id);

    return ACCOUNT_RESPONSE_MIN_LENGTH;
}

/**
 * @brief Makes directory.
 *
 * @param p_client Client (stores request).
 * @param p_response Response to send.
 *
 * @return Length of response on success, otherwise -1.
 */
int
make_directory(FTP_ctx *p_client, FTP_Message *p_response)
{

    if (!p_client)
    {
        fprintf(stderr, "Make_directory Error: NULL ptr\n");
        return -1;
    }

    p_response->opcode = SUCCESS;

    Make_Dir_Request *p_request = (Make_Dir_Request *)&p_client->message;

    p_request->dir_name_len = ntohs(p_request->dir_name_len);
    p_request->session_id   = ntohl(p_request->session_id);

    if (p_request->session_id != p_client->session_id)
    {
        p_response->opcode = SESSION_ERROR;
        goto END;
    }

    struct stat tmp = { 0 };

    char *p_server_dir = p_client->p_server_ctx->p_server_dir;

    if (validate_path(p_server_dir, p_request->p_dir_name, true) != 0)
    {
        p_response->opcode = FAILURE;
        goto END;
    }

    if (mkdir(p_request->p_dir_name, S_IRWXU) == -1)
    {
        perror("Make_directory Error");
        p_response->opcode = FAILURE;
    }

END:
    return 1;
}

/**
 * @brief Deletes a file.
 *
 * @param p_client Client (stores request).
 * @param p_response Response to send.
 *
 * @return Length of response on success, otherwise -1.
 */
int
delete_file(FTP_ctx *p_client, FTP_Message *p_response)
{
    if (!p_client)
    {
        fprintf(stderr, "Delete_file Error: NULL ptr\n");
        return -1;
    }

    Delete_File_Request *p_request = (Delete_File_Request *)&p_client->message;

    p_request->filename_len = ntohs(p_request->filename_len);
    p_request->session_id   = ntohl(p_request->session_id);

    if (p_request->session_id != p_client->session_id)
    {
        p_response->opcode = SESSION_ERROR;
        goto END;
    }

    p_response->opcode = SUCCESS;

    char *p_server_dir = p_client->p_server_ctx->p_server_dir;

    if (validate_path(p_server_dir, p_request->p_file_name, true) != 0)
    {
        p_response->opcode = FAILURE;
        goto END;
    }

    if (remove(p_request->p_file_name) == -1)
    {
        perror("Delete_file Error");
        p_response->opcode = FAILURE;
    }

END:
    return 1;
}

/**
 * @brief Get a file.
 *
 * @param p_client Client (stores request).
 * @param p_response Response to send.
 *
 * @return Length of response on success.
 */
int
get_file(FTP_ctx *p_client, Get_File_Response *p_response)
{

    if (!p_client || !p_response)
    {
        fprintf(stderr, "Get_file Error: NULL ptr\n");
        return -1;
    }

    Get_File_Request *p_request = (Get_File_Request *)&p_client->message;

    int response_len = GET_FILE_RESPONSE_MIN_LENGTH;
    int file_sz      = -1;

    char *p_file_name = NULL;

    FILE *ph_file = NULL;

    p_request->filename_len = ntohs(p_request->filename_len);
    p_request->session_id   = ntohl(p_request->session_id);

    if (p_request->session_id != p_client->session_id)
    {
        p_response->code = SESSION_ERROR;
        goto END;
    }

    if ((p_file_name = strndup(p_request->p_file_name, p_request->filename_len))
        == NULL)
    {
        fprintf(stderr, "Get_file Error: strdup\n");
        p_response->code = FAILURE;
        goto END;
    }

    if (validate_path(p_client->p_server_ctx->p_server_dir, p_file_name, true)
        != 0)
    {
        p_response->code = FAILURE;
        goto END;
    }

    if ((ph_file = fopen(p_file_name, "r+")) == NULL)
    {
        perror("Get_file Error");
        p_response->code = FAILURE;
        goto END;
    }

    if ((file_sz = read_file(p_response, ph_file)) == -1)
    {
        p_response->code = FAILURE;
    }
    else
    {
        response_len += file_sz;
        p_response->length = htonl(file_sz);
        p_response->code   = SUCCESS;
    }

END:
    if (ph_file)
    {
        fclose(ph_file);
    }

    if (p_file_name)
    {
        free(p_file_name);
    }

    return response_len;
}

/**
 * @brief Writes file data into response.
 *
 * @param p_response Response.
 * @param ph_file Pointer to file.
 *
 * @return Number of bytes read from file on success, otherwise -1.
 */
int
read_file(Get_File_Response *p_response, FILE *ph_file)
{

    if (!p_response || !ph_file)
    {
        fprintf(stderr, "Read_file Error: NULL ptr\n");
        return -1;
    }

    size_t file_sz = 0;

    ssize_t bytes_read = 0;

    if (fseek(ph_file, 0L, SEEK_END) == -1)
    {
        perror("Read_file Error");
        return -1;
    }

    file_sz = ftell(ph_file);

    if (fseek(ph_file, 0L, SEEK_SET) == -1)
    {
        perror("Read_file Error");
        return -1;
    }

    if (file_sz > MAXE_FILE_SIZE)
    {
        fprintf(stderr, "Read_file Error: file is too large\n");
        return -1;
    }

    if ((bytes_read = fread(p_response->p_file_data, 1, file_sz, ph_file))
        == -1)
    {
        perror("Read_file Error read");
        return -1;
    }

    if ((size_t)bytes_read != file_sz)
    {
        fprintf(stderr,
                "Read_file Error: fread r: %ld e: %lu\n",
                bytes_read,
                file_sz);
        return -1;
    }

    return bytes_read;
}

/**
 * @brief Put a file.
 *
 * @param p_client Client (stores request).
 * @param p_response Response to send.
 *
 * @return Length of response on succcess, otherwises -1.
 */
int
put_file(FTP_ctx *p_client, FTP_Message *p_response)
{

    if (!p_client)
    {
        fprintf(stderr, "Put_file Error: NULL ptr\n");
        return -1;
    }

    Put_File_Request *p_request   = (Put_File_Request *)&p_client->message;
    char             *p_file_name = NULL;
    FILE             *ph_file     = NULL;

    p_request->filename_len = ntohs(p_request->filename_len);
    p_request->session_id   = ntohl(p_request->session_id);
    p_request->length       = ntohl(p_request->length);

    if (p_request->session_id != p_client->session_id)
    {
        p_response->opcode = SESSION_ERROR;
        goto END;
    }

    if ((p_file_name = strndup(p_request->p_file_data, p_request->filename_len))
        == NULL)
    {
        fprintf(stderr, "Put_file Error: strdup\n");
        p_response->opcode = FAILURE;
        goto END;
    }

    if (validate_path(p_client->p_server_ctx->p_server_dir, p_file_name, true)
        != 0)
    {
        p_response->opcode = FAILURE;
        goto END;
    }

    if (NO_OVERWRITE == p_request->flag)
    {
        if (access(p_file_name, F_OK) == 0)
        {
            p_response->opcode = FILE_EXISTS;
            goto END;
        }
    }

    if ((ph_file = fopen(p_file_name, "w+")) == NULL)
    {
        perror("Put_file Error");
        p_response->opcode = FAILURE;
        goto END;
    }

    if (fwrite(p_request->p_file_data + p_request->filename_len,
               1,
               p_request->length,
               ph_file)
        != p_request->length)
    {
        fprintf(stderr, "Write_file Error: fwrite error\n");

        p_response->opcode = FAILURE;
    }

    p_response->opcode = SUCCESS;

END:
    if (ph_file)
    {
        fclose(ph_file);
    }
    if (p_file_name)
    {
        free(p_file_name);
    }

    return 1;
}

/**
 * @brief List directory contents.
 *
 * @param p_client Client (stores request).
 * @param p_response Response to send.
 *
 * @return Length of response on success, otherwise -1.
 */
int
list_dir(FTP_ctx *p_client, List_Dir_Response *p_response)
{

    if (!p_client)
    {
        fprintf(stderr, "List_dir Error: NULL ptr\n");
        return -1;
    }

    List_Dir_Request *p_request = (List_Dir_Request *)&p_client->message;

    DIR *ph_dir = NULL;

    struct dirent *p_file = NULL;

    char *p_buf     = NULL;
    char *p_buf_ptr = NULL;

    ssize_t char_count = 0;
    ssize_t bytes      = 0;

    uint8_t file_type    = 0;
    int     response_len = 0;

    p_request->dir_name_len = ntohs(p_request->dir_name_len);
    p_request->session_id   = ntohl(p_request->session_id);
    p_request->current_pos  = ntohl(p_request->current_pos);

    if (p_request->session_id != p_client->session_id)
    {
        p_response->code = SESSION_ERROR;
        response_len     = LIST_DIR_RESPONSE_MIN_LENGTH;
        goto END;
    }

    if (validate_path(
            p_client->p_server_ctx->p_server_dir, p_request->p_dir_name, false)
        != 0)
    {
        p_response->code = FAILURE;
        response_len     = LIST_DIR_RESPONSE_MIN_LENGTH;
        goto END;
    }

    if ((ph_dir = opendir(p_request->p_dir_name)) == NULL)
    {
        perror("List_dir Error");
        p_response->code = FAILURE;
        response_len     = LIST_DIR_RESPONSE_MIN_LENGTH;
        goto END;
    }

    // Set errno to 0 before readdir call to check for error.
    //
    errno = 0;

    // Count number of bytes of each normal file/dir name in directory.
    //
    while ((p_file = readdir(ph_dir)))
    {

        // Only get files and directories.
        //
        if ((p_file->d_type != DT_DIR) && (p_file->d_type != DT_REG))
        {
            continue;
        }

        char_count += strnlen(p_file->d_name, LS_REQUEST_DATA_MAX_LENGTH);

        // File type and null byte.
        //
        char_count += 2;
    }

    if (errno != 0)
    {
        perror("List_dir Error");
        p_response->code = FAILURE;
        response_len     = LIST_DIR_RESPONSE_MIN_LENGTH;
        goto END;
    }

    if ((p_buf = calloc(char_count, sizeof(*p_buf))) == NULL)
    {
        fprintf(stderr, "List_dir Error: Calloc\n");
        p_response->code = FAILURE;
        response_len     = LIST_DIR_RESPONSE_MIN_LENGTH;
        goto END;
    }

    // Set pointer to walk buffer.
    //
    p_buf_ptr = p_buf;

    rewinddir(ph_dir);

    // Set errno to 0 before readdir call to check for error.
    //
    errno = 0;

    // Write file names to buffer.
    //
    while ((p_file = readdir(ph_dir)))
    {
        if (DT_DIR == p_file->d_type)
        {
            file_type = DIRECTORY;
        }
        else if (DT_REG == p_file->d_type)
        {
            file_type = REG_FILE;
        }
        else
        {
            continue;
        }

        // Write file name.
        //
        bytes = sprintf(p_buf_ptr, "%d%s", file_type, p_file->d_name);

        // NULL byte.
        //
        bytes++;

        // Walk pointer.
        //
        p_buf_ptr += bytes;

        bytes = 0;
    }

    if (errno != 0)
    {
        perror("List_dir Error");
        p_response->code = FAILURE;
        response_len     = LIST_DIR_RESPONSE_MIN_LENGTH;
        goto END;
    }

    if ((response_len = write_dir(p_client, p_response, p_buf, char_count))
        == -1)
    {
        p_response->code = FAILURE;
        response_len     = LIST_DIR_RESPONSE_MIN_LENGTH;
    }

END:

    if (ph_dir)
    {
        if (closedir(ph_dir) == -1)
        {
            perror("List_dir Error");
        }
    }

    if (p_file)
    {
        free(p_file);
    }

    if (p_buf)
    {
        free(p_buf);
    }

    return response_len;
}

/**
 * @brief Write directory contents to response.
 *
 * @param p_client Client (stores request).
 * @param p_response Response to send.
 * @param p_buf All directory contents.
 * @param len Length of all directory contents.
 *
 * @return Length of response on success, otherwise -1.
 */
int
write_dir(FTP_ctx           *p_client,
          List_Dir_Response *p_response,
          char              *p_buf,
          ssize_t            buf_len)
{
    if (!p_client || !p_buf)
    {
        fprintf(stderr, "Send_dir Error: NULL ptr\n");
        return -1;
    }

    List_Dir_Request *p_request = (List_Dir_Request *)&p_client->message;

    ssize_t  bytes       = 0;
    ssize_t  bytes_left  = (buf_len - p_request->current_pos);
    uint32_t length      = 0;
    uint32_t current_pos = 0;

    char *p_buf_ptr = NULL;

    if (p_request->current_pos > buf_len)
    {
        fprintf(stderr, "Send_dir Error: Current position out of bounds\n");
        return -1;
    }

    p_buf_ptr = (p_buf + p_request->current_pos);

    p_response->total_length = htonl(buf_len);
    p_response->code         = SUCCESS;

    if (bytes_left > LS_RESPONSE_DATA_MAX_LENGTH)
    {
        length = LS_RESPONSE_DATA_MAX_LENGTH;
        p_response->current_pos += LS_RESPONSE_DATA_MAX_LENGTH;
    }
    else
    {
        length = bytes_left;
        current_pos += bytes_left;
    }

    // Writes the ls data, the server current position and the length of current
    // ls data.
    //
    memcpy(p_response->p_ls_data, (p_buf_ptr + p_request->current_pos), length);

    p_response->length      = htonl(length);
    p_response->current_pos = htonl(current_pos);

    return length + LIST_DIR_RESPONSE_MIN_LENGTH;
}

/**
 * @brief Make sure path is within server home directory.
 *
 * @param p_server_dir Server home directory.
 * @param p_path Path to validate.
 * @param b_is_file If path is a file or a directory.
 * @return Returns 0 on success, otherwise -1.
 */
int
validate_path(char *p_server_dir, char *p_path, bool b_is_file)
{

    if (!p_server_dir || !p_path)
    {
        fprintf(stderr, "Validate_path Error: NULL ptr\n");
        return -1;
    }

    int  ret                   = 0;
    char p_full_path[PATH_MAX] = { '\0' };

    char *p_forward_slash_ptr = NULL;

    // Remove final forward slash to see if parent directory is valid.
    //
    if (b_is_file)
    {
        p_forward_slash_ptr = strrchr(p_path, '/');

        // Second part is for ex. "new_dir/".
        //
        if (p_forward_slash_ptr && (*(p_forward_slash_ptr + 1) != '\0'))
        {
            *p_forward_slash_ptr = '\0';
        }
        else
        {
            ret = 0;
            goto END;
        }
    }

    // Get the full path.
    //
    if (realpath(p_path, p_full_path) == NULL)
    {
        fprintf(
            stderr, "Validate_path Error: Path '%s' does not exist\n", p_path);
        ret = -1;
        goto END;
    }

    // See if server path is in new path.
    //
    if (strstr(p_full_path, p_server_dir) == NULL)
    {
        fprintf(stderr,
                "Validate_path Error: Path '%s' is oustide server directory\n",
                p_full_path);
        ret = -1;
    }

END:
    if (p_forward_slash_ptr)
    {
        *p_forward_slash_ptr = '/';
    }

    return ret;
}

/**
 * @brief Generate session ID.
 *
 * @param p_request Account request with username and password to be hashed.
 * @return Session ID.
 */
uint32_t
generate_session_id(Account_Request *p_request)
{
    // This based on: djb2 hash
    // Name: Dan Bernstein
    // Location: http://www.cse.yorku.ca/~oz/hash.html

    uint32_t hash = 5381;
    int      c;

    size_t size       = (p_request->name_len + p_request->password_len);
    void  *p_byte_ptr = p_request->p_credentials;
    size_t count      = 0;

    while (count != size)
    {
        c          = *(char *)p_byte_ptr;
        hash       = ((hash << 5) + hash) + c; /* hash * 33 + c */
        p_byte_ptr = (char *)p_byte_ptr + 1;
        count++;
    }
    return hash;
}

/*** end of file ***/
