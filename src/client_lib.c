/** @file client_lib.c
 *
 * @brief Add or delete clients.
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
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/epoll.h>

#include "client_lib.h"

/**
 * @brief Alloc's clients.
 *
 * @param len Max number of clients
 *
 * @return Pointer to alloc'd clients.
 */
Clients *
init_clients(size_t len)
{
    Clients *p_clients = NULL;

    p_clients = calloc(1, sizeof(*p_clients));

    if (!p_clients)
    {
        fprintf(stderr, "Init_clients Error: Calloc\n");
        return NULL;
    }

    if (pthread_mutex_init(&p_clients->lock, NULL) != 0)
    {
        fprintf(stderr, "Init_pool Error: pthread_mutex_init\n");
        free(p_clients);
        return NULL;
    }

    p_clients->pp_clients = calloc(len, sizeof(p_clients->pp_clients));

    if (!p_clients->pp_clients)
    {
        fprintf(stderr, "Init_clients Error: Calloc\n");
        free(p_clients);
        return NULL;
    }

    p_clients->capacity = len;

    return p_clients;
}

/**
 * @brief Free's clients.
 *
 * @param pp_clients Clients array pointer.
 *
 * @return 0 on success, otherwise -1.
 */
int
destroy_clients(Clients **pp_clients)
{
    int ret = 0;

    if (!pp_clients || !*pp_clients || !(*pp_clients)->pp_clients)
    {
        fprintf(stderr, "Destroy_clients Error: NULL ptr\n");
        ret = -1;
        goto END;
    }

    Clients *c = *pp_clients;

    int err = 0;

    if ((err = pthread_mutex_destroy(&c->lock)) != 0)
    {
        fprintf(
            stderr, "Destroy_clients Error: mutex_destroy %s\n", strerror(err));
        ret = -1;
    }

    for (size_t client = 0; client < c->count; client++)
    {
        close(c->pp_clients[client]->client.h_sock);
        free(c->pp_clients[client]);
    }

    free(c->pp_clients);

    free(c);

    *pp_clients = NULL;

END:
    return ret;
}

/**
 * @brief Add client to clients.
 *
 * @param p_server_ctx Server context (stores clients).
 * @param h_sock Client socket.
 *
 * @return 0 on success, otherwise -1.
 */
int
add_client(Server_ctx *p_server_ctx, int h_sock)
{
    if (!p_server_ctx)
    {
        fprintf(stderr, "Add_client Error: NULL ptr\n");
        raise(SIGINT); // Deemed critical error. Try to exit gracefully.
    }

    FTP_ctx           *p_client  = NULL;
    Clients           *p_clients = p_server_ctx->p_clients;
    struct epoll_event event     = { 0 };

    if (p_clients->count == p_clients->capacity)
    {
        fprintf(stderr, "Add_client Error: Capcity reached\n");
        return -1;
    }

    p_client = calloc(1, sizeof(*p_client));

    if (!p_client)
    {
        fprintf(stderr, "Add_client Error: Calloc\n");
        return -1;
    }

    p_client->session_id    = -1;
    p_client->p_server_ctx  = p_server_ctx;
    p_client->last_activity = time(NULL);
    p_client->client.h_sock = h_sock;

    event.events  = EPOLLIN | EPOLLET | EPOLLONESHOT;
    event.data.fd = h_sock;

    p_clients->pp_clients[p_clients->count] = p_client;

    p_client->pos = p_clients->count;

    p_clients->count++;

    if (epoll_ctl(p_server_ctx->h_epoll_fd, EPOLL_CTL_ADD, h_sock, &event)
        == -1)
    {
        perror("Add_client Error");
    }

    return 0;
}

/**
 * @brief Delete client from clients.
 *
 * @param p_server_ctx Server context.
 * @param p_client Client to be deleted.
 *
 * @return 0 on success, otherwise -1.
 */
int
delete_client(Server_ctx *p_server_ctx, FTP_ctx *p_client)
{
    if (!p_server_ctx || !p_client)
    {
        fprintf(stderr, "Delete_client Error: NULL ptr\n");
        return -1;
    }

    if (pthread_mutex_lock(&p_server_ctx->p_clients->lock) != 0)
    {
        fprintf(stderr, "Delete_client Error: mutex_lock\n");
        return -1;
    }

    Clients *p_clients = p_server_ctx->p_clients;

    size_t pos = p_client->pos;

    // If client is at end of array, just remove it.
    //
    if (pos == (p_clients->count - 1))
    {
        close(p_clients->pp_clients[pos]->client.h_sock);
        free(p_clients->pp_clients[pos]);

        p_clients->pp_clients[pos] = NULL;
    }

    // Else, swap with the back of the array and remove it.
    //
    else
    {
        close(p_clients->pp_clients[pos]->client.h_sock);
        free(p_clients->pp_clients[pos]);

        p_clients->pp_clients[pos]
            = p_clients->pp_clients[p_clients->count - 1];

        p_clients->pp_clients[pos]->pos             = pos;
        p_clients->pp_clients[p_clients->count - 1] = NULL;
    }

    p_clients->count--;

    if (pthread_mutex_unlock(&p_clients->lock) != 0)
    {
        fprintf(stderr, "Delete_client Error: mutext_unlock\n");
        return -1;
    }

    return 0;
}

/*** end of file ***/