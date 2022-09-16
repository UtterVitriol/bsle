/** @file net_lib.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/errno.h>
#include <signal.h>

#include "net_lib.h"
#include "client_lib.h"
#include "accounts.h"
#include "thread_pool.h"
#include "ftp_lib.h"

/**
 * @brief Allocates server resources.
 *
 * @param p_server_ctx Server context
 * @param port Port number to listen.
 * @param p_input_dir Server home directory.
 * @param timeout Server session timeout.
 *
 * @return 0 on success, otherwise -1.
 */
int
server_startup(Server_ctx *p_server_ctx,
               int         port,
               char       *p_input_dir,
               time_t      timeout)
{
    puts("Setting up server");

    if (!p_server_ctx || !p_input_dir)
    {
        fprintf(stderr, "Server_startup Error: NULL ptr\n");

        return -1;
    }

    if (sock_create(&p_server_ctx->server, port) == -1)
    {
        return -1;
    }

    // Get full path to server home directory.
    //
    if (realpath(p_input_dir, p_server_ctx->p_server_dir) == NULL)
    {
        fprintf(stderr,
                "Server_startup Error: directory '%s' not found\n",
                p_input_dir);
        return -1;
    }

    if (chdir(p_server_ctx->p_server_dir) == -1)
    {
        perror("Server_startup Error");
        return -1;
    }

    p_server_ctx->timeout    = timeout;
    p_server_ctx->p_accounts = init_table(1000, free_account);

    if (!p_server_ctx->p_accounts)
    {
        return -1;
    }

    if (pthread_mutex_init(&p_server_ctx->lock, NULL) != 0)
    {
        fprintf(stderr, "Server_startup Error: pthread_mutex_init\n");
        return -1;
    }

    // Create default admin account.
    //
    char p_admin_creds[] = "adminpassword";

    Account_Request create_admin = { 0 };
    create_admin.flag            = ADMIN;
    create_admin.name_len        = 5;
    create_admin.password_len    = 8;

    memcpy(create_admin.p_credentials, p_admin_creds, sizeof(p_admin_creds));

    if (add_account(&create_admin, p_server_ctx->p_accounts) != 0)
    {
        fprintf(stderr,
                "Server_startup Error: Admin account creation failed\n");
        return -1;
    }

    p_server_ctx->p_pool = init_pool(2, 1000);

    if (!p_server_ctx->p_pool)
    {
        return -1;
    }

    p_server_ctx->p_clients = init_clients(1000);

    if (!p_server_ctx->p_clients)
    {
        return -1;
    }

    printf("Client timeout set to: %s(%ld) seconds\n",
           600 == timeout ? "default " : "",
           timeout);
    printf("Server directory set to: '%s'\n", p_server_ctx->p_server_dir);
    printf(
        "Listening on port: %s(%d)\n", 26669 == port ? "default " : "", port);
    puts("Server setup finished");

    return 0;
}

/**
 * @brief Free's server resources.
 *
 * @param p_server_ctx Server context
 *
 * @return int
 */
int
server_shutdown(Server_ctx *p_server_ctx)
{
    int ret = 0;

    if (destroy_pool(&p_server_ctx->p_pool) == -1)
    {
        ret = 1;
    }
    if (destroy_clients(&p_server_ctx->p_clients) == -1)
    {
        ret = 1;
    }
    if (destroy_table(&p_server_ctx->p_accounts) == -1)
    {
        ret = 1;
    }

    return ret;
}

/**
 * @brief Creates server socket.
 *
 * @param p_server Socket structer.
 * @param port Port to listen.
 *
 * @return 0 on success, otherwise -1.
 */
int
sock_create(Socket *p_server, int port)
{
    // Check for NULL ptr
    if (!p_server)
    {
        fprintf(stderr, "Sock_create Error: NULL ptr\n");
        return -1;
    }

    p_server->addr.sin_family = AF_INET;

    p_server->addr.sin_port = htons(port);

    if ((p_server->h_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Socket Creation Error");
        return -1;
    }

    int opt = 1;

    if (setsockopt(p_server->h_sock,
                   SOL_SOCKET,
                   SO_REUSEADDR | SO_REUSEPORT,
                   &opt,
                   sizeof(opt)))
    {
        perror("Setsockopt Error");
        return -1;
    }

    if (bind(p_server->h_sock,
             (struct sockaddr *)&p_server->addr,
             sizeof(p_server->addr))
        < 0)
    {
        perror("Bind Error");
        return -1;
    }

    if (listen(p_server->h_sock, 50) < 0)
    {
        perror("Listen Error");
        return -1;
    }

    return 0;
}

/**
 * @brief Adds client connections to clients and messages to jobs.
 *
 * @param p_server_ctx Server context.
 *
 * @return 0 never, -1 otherwise.
 */
int
client_wait(Server_ctx *p_server_ctx)
{
    int ret     = 0;
    int addrlen = sizeof(p_server_ctx->server.addr);

    FTP_ctx *ftp_ctx = NULL;

    int                event_count     = 0;
    struct epoll_event server_settings = { 0 };
    struct epoll_event events[10]      = { 0 };

    p_server_ctx->h_epoll_fd = epoll_create1(0);

    if (p_server_ctx->h_epoll_fd == -1)
    {
        fprintf(stderr, "EPOLL BAD\n");
        return -1;
    }

    server_settings.events  = EPOLLIN | EPOLLPRI;
    server_settings.data.fd = p_server_ctx->server.h_sock;

    if (epoll_ctl(p_server_ctx->h_epoll_fd,
                  EPOLL_CTL_ADD,
                  p_server_ctx->server.h_sock,
                  &server_settings))
    {
        perror("Client_wait Error");
        close(p_server_ctx->h_epoll_fd);
        return -1;
    }

    for (;;)
    {
        event_count = epoll_wait(p_server_ctx->h_epoll_fd, events, 100, -1);

        for (int event = 0; event < event_count; event++)
        {

            if (events[event].data.fd == p_server_ctx->server.h_sock)
            {
                if ((ret = accept(p_server_ctx->server.h_sock,
                                  (struct sockaddr *)&p_server_ctx->server.addr,
                                  (socklen_t *)&addrlen))
                    < 0)
                {
                    perror("Client_wait Error");
                    return -1;
                }

                // If the server is full, close the new connection.
                //
                if (add_client(p_server_ctx, ret) == -1)
                {
                    close(ret);
                }

                continue;
            }

            if (pthread_mutex_lock(&p_server_ctx->p_clients->lock) != 0)
            {
                fprintf(stderr, "Client_wait Error: mutex_lock\n");
                raise(SIGINT); // Deemed critical error. Try to exit gracefully.
            }

            for (size_t client = 0; client < p_server_ctx->p_clients->count;
                 client++)
            {
                if (events[event].data.fd
                    == p_server_ctx->p_clients->pp_clients[client]
                           ->client.h_sock)
                {

                    if (add_job(p_server_ctx->p_pool,
                                handle_client,
                                p_server_ctx->p_clients->pp_clients[client])
                        == -1)
                    {
                        modify_client_epoll_event(
                            p_server_ctx->p_clients->pp_clients[client]);
                    }
                }
            }

            if (pthread_mutex_unlock(&p_server_ctx->p_clients->lock) != 0)
            {
                fprintf(stderr, "Client_wait Error: mutex_unlock\n");
                raise(SIGINT); // Deemed critical error. Try to exit gracefully.
            }
        }
    }

    return 0;
}

/**
 * @brief Handles single client request and response.
 *
 * @param p_ctx Client.
 *
 * @return 0 on success, otherwise -1.
 */
int
handle_client(void *p_ctx)
{
    // Use exit(1) here for cleanup becuase I was not able to come up with
    // a simple solution. But, the chances of it actually happening are small.
    //
    if (!p_ctx)
    {
        fprintf(stderr, "Handle_client Error: NULL ptr\n");
        return -1;
    }

    int         ret      = 0;
    FTP_ctx    *p_client = (FTP_ctx *)p_ctx;
    FTP_Message response = { 0 };
    time_t      now      = 0;

    now = time(NULL);

    if ((now - p_client->last_activity) > p_client->p_server_ctx->timeout)
    {
        p_client->session_id = -1;
    }
    else
    {
        p_client->last_activity = now;
    }

    if ((p_client->message_length = recv(p_client->client.h_sock,
                                         (void *)&p_client->message,
                                         MAX_MESSAGE_LENGTH,
                                         0))
        == -1)
    {

        perror("Handle_client Error");
    }

    if (p_client->message_length <= 0)
    {
        if (delete_client(p_client->p_server_ctx, p_client) == -1)
        {
            exit(1);
        }
        return 0;
    }

    if (pthread_mutex_lock(&p_client->p_server_ctx->lock) != 0)
    {
        fprintf(stderr, "Handle_client Error: mutex_lock\n");
        exit(1);
    }

    if ((ret = ftp_get_command(p_client, &response)) == -1)
    {
        exit(1);
    }

    if (pthread_mutex_unlock(&p_client->p_server_ctx->lock) == -1)
    {
        fprintf(stderr, "Handle_client Error: mutex_unlock\n");
        exit(1);
    }

    if (send(p_client->client.h_sock, &response, ret, 0) == -1)
    {
        perror("Handle_client Error");
        if (delete_client(p_client->p_server_ctx, p_client) == -1)
        {
            exit(1);
        }
        return 0;
    }

    bzero(&p_client->message, sizeof(p_client->message));

    if (modify_client_epoll_event(p_client) == -1)
    {
        if (delete_client(p_client->p_server_ctx, p_client) == -1)
        {
            exit(1);
        }
    }

    return 0;
}

/**
 * @brief Makes epoll care about client again.
 *
 * @param p_ftp_ctx Client.
 * @return 0 on success, otherwise -1.
 */
int
modify_client_epoll_event(FTP_ctx *p_client)
{
    if (!p_client)
    {
        fprintf(stderr, "Finish_loop Error: NULL ptr\n");
        return -1;
    }

    struct epoll_event event = { 0 };
    event.events             = EPOLLIN | EPOLLET | EPOLLONESHOT;
    event.data.fd            = p_client->client.h_sock;

    if (epoll_ctl(p_client->p_server_ctx->h_epoll_fd,
                  EPOLL_CTL_MOD,
                  p_client->client.h_sock,
                  &event))
    {
        perror("Finish_loop Error");
        return -1;
    }

    return 0;
}

/*** end of file ***/