#!/usr/bin/env python3
"""Capstone python client.

Handles command line arguments and drives FTPClient.
"""

import argparse
import ftp_client


def setup_arg_parser():
    """Create argument parser

    Instanitates ArgumentParser and adds arguments.

    Returns:
        Initialized ArgumentParser with arguments.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('username',
                        metavar='USERNAME',
                        nargs=1,
                        type=str,
                        help='remote ftp account username')

    parser.add_argument('password',
                        metavar='PASSWORD',
                        nargs=1,
                        type=str,
                        help='remote ftp account password')

    parser.add_argument('host',
                        metavar='HOST',
                        nargs=1,
                        type=str,
                        help='remote ftp host address')

    parser.add_argument('port',
                        metavar='PORT',
                        nargs=1,
                        type=int,
                        help='remote ftp host port')

    parser.add_argument('-o',
                        '--overwrite',
                        action='store_true',
                        help='when present with the put flag, will cause'
                        ' files to be overwritten on the server')

    commands_group = parser.add_mutually_exclusive_group()

    commands_group.add_argument(
        '-create_user',
        metavar=(('USERNAME', 'PASSWORD', 'PERMISSIONS')),
        nargs=3,
        type=str,
        help='creates user with permissions (READ_ONLY, READ_WRITE or ADMIN)')

    commands_group.add_argument('-delete_user',
                                metavar=('USERNAME'),
                                nargs=1,
                                type=str,
                                help='deletes user')

    commands_group.add_argument('-get',
                                metavar=('SRC', 'DST'),
                                nargs=2,
                                type=str,
                                help='gets a file from server src path'
                                ' and copies it to the client dst path')

    commands_group.add_argument('-put',
                                metavar=('SRC', 'DST'),
                                nargs=2,
                                type=str,
                                help='sends a file from client src path'
                                ' to be placed in the server dst path')

    commands_group.add_argument('-delete',
                                metavar='PATH',
                                nargs=1,
                                type=str,
                                help='deletes file at server path')

    commands_group.add_argument('-mkdir',
                                metavar='PATH',
                                nargs=1,
                                type=str,
                                help='makes directory at server path')

    commands_group.add_argument('-ls',
                                metavar='PATH',
                                nargs='?',
                                const='/',
                                type=str,
                                help='lists remote directory contents')

    return parser


def main():
    parser = setup_arg_parser()
    args = parser.parse_args()

    try:
        with ftp_client.FTPClient(*args.host, *args.port) as client:

            client.user_operation(*args.username, *args.password, silent=True)

            if args.create_user:
                client.user_operation(*args.create_user)
            elif args.delete_user:
                client.user_operation(*args.delete_user, action="DELETE")
            elif args.get:
                client.get_file(*args.get)
            elif args.put:
                client.put_file(*args.put, args.overwrite)
            elif args.delete:
                client.delete_file(*args.delete)
            elif args.ls:
                client.list_dir(args.ls)
            elif args.mkdir:
                client.make_dir(*args.mkdir)
            else:
                client.interactive()
    except ftp_client.PermissionInvalidError as e:
        print(e)
        parser.print_help()
        return
    except ftp_client.FTPClientError as e:
        print(e)
        return


if __name__ == "__main__":
    main()
