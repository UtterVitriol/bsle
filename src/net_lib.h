/** @file net_lib.h
 *
 * @brief Handles sockets.
 *
 * @par
 * COPYRIGHT NOTICE: (c) 2022 U.S. Army. All rights reserved. This software is
 * placed in the public domain and may be used for any purpose, as long as that
 * purpose is in service of the United States Army. HOOAH! However, this notice
 * must not be changed or removed. No warranty is expressed or implied by the
 * publication or distribution of this source code.
 */

#ifndef NET_LIB_H
#define NET_LIB_H

#include <netdb.h>
#include <limits.h>
#include <pthread.h>

#include "hash_table.h"
#include "thread_pool.h"

typedef struct FTP_Context FTP_ctx;
typedef struct Server_ctx  Server_ctx;

#include "client_lib.h"

typedef struct Socket
{
    int                h_sock;
    struct sockaddr_in addr;
} Socket;

typedef struct __attribute__((__packed__)) FTP_Message
{
    uint8_t opcode;
    char    p_data[2047];
} FTP_Message;

struct Server_ctx
{
    char            p_server_dir[PATH_MAX];
    Table          *p_accounts;
    Socket          server;
    Thread_Pool    *p_pool;
    Clients        *p_clients;
    pthread_mutex_t lock;
    time_t          timeout;
    int             h_epoll_fd;
};

struct __attribute__((__packed__)) FTP_Context
{
    Socket      client;
    FTP_Message message;
    ssize_t     message_length;
    int64_t     session_id;
    uint8_t     auth_level;
    size_t      pos;
    time_t      last_activity;
    Server_ctx *p_server_ctx;
};

int server_startup(Server_ctx *p_server_ctx,
                   int         port,
                   char       *p_input_dir,
                   time_t      timeout);

int server_shutdown(Server_ctx *p_server_ctx);

int sock_create(Socket *p_sock, int port);

int client_wait(Server_ctx *p_server_ctx);

int handle_client(void *p_ctx);

int modify_client_epoll_event(FTP_ctx *p_client);

#endif /* NET_LIB_H */

/*** end of file ***/