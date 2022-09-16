/** @file client_lib.h
 *
 * @brief Add or delete clients.
 * @par
 * COPYRIGHT NOTICE: (c) 2022 U.S. Army. All rights reserved. This software is
 * placed in the public domain and may be used for any purpose, as long as that
 * purpose is in service of the United States Army. HOOAH! However, this notice
 * must not be changed or removed. No warranty is expressed or implied by the
 * publication or distribution of this source code.
 */

#ifndef CLIENT_LIB_H
#define CLIENT_LIB_H

typedef struct Clients Clients;

#include "net_lib.h"

struct Clients
{
    FTP_ctx       **pp_clients;
    size_t          capacity;
    size_t          count;
    pthread_mutex_t lock;
};

Clients *init_clients(size_t len);
int      destroy_clients(Clients **pp_clients);
int      add_client(Server_ctx *p_server_ctx, int h_sock);
int      delete_client(Server_ctx *p_server_ctx, FTP_ctx *p_client_ptr);

#endif /* CLIENT_LIB_H */

/*** end of file ***/