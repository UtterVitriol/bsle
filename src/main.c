/** @file main.c
 *
 * @brief Main.
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

#include "net_lib.h"

Server_ctx g_server_ctx = { 0 };

/**
 * @brief Exits program.
 *
 * @param unused Not really sure. Not going to look it up.
 */
void
handle_sigint(int unused)
{
    (void)unused;
    int ret = 0;

    static int b_shutdown = 0;

    if (b_shutdown)
    {
        return;
    }

    b_shutdown = 1;

    puts("Shutting Down");

    ret = server_shutdown(&g_server_ctx);
    exit(ret);
}

/**
 * @brief Prints program help.
 *
 * @param p_name Program name.
 */
void
print_help(char *p_name)
{
    fprintf(stderr,
            "usage: %s -t [timeout] -d directory -p [port]\n\n"
            "-t\tclient session timeout (default: 600 seconds)\n"
            "-d\tserver home directory\n"
            "-p\tport: {1024 - 65535} (default: 23669)\n",
            p_name);
}

/**
 * @brief Capistone.
 *
 * @param argc Number of cli arguments.
 * @param pp_argv Cli arguments.
 *
 * @return 0 on success, otherwisie 1.
 */
int
main(int argc, char **pp_argv)
{
    signal(SIGINT, handle_sigint);
    signal(SIGPIPE, SIG_IGN);

    int    opt;
    int    port                   = 26669;
    time_t timeout                = 600;
    char   p_server_dir[PATH_MAX] = { '\0' };

    if ((argc < 3) || (argc > 7))
    {
        print_help(pp_argv[0]);
        return 1;
    }

    while ((opt = getopt(argc, pp_argv, "t:d:p:")) != -1)
    {
        switch (opt)
        {
            case 't':
                timeout = strtol(optarg, NULL, 10);
                break;

            case 'd':
                memcpy(p_server_dir, optarg, strlen(optarg));
                break;
            case 'p':
                port = strtol(optarg, NULL, 10);
                if ((port < 1024) || (port > 65535))
                {
                    fprintf(stderr,
                            "%s: invalid port number -- '%s'\n",
                            pp_argv[0],
                            optarg);
                    print_help(pp_argv[0]);
                    return 1;
                }
                break;
            default:
                print_help(pp_argv[0]);
                return 1;
        }
    }

    if (server_startup(&g_server_ctx, port, p_server_dir, timeout) == -1)
    {
        return server_shutdown(&g_server_ctx);
    }

    if (client_wait(&g_server_ctx) == -1)
    {
        return server_shutdown((&g_server_ctx));
    }
}

/*** end of file ***/
