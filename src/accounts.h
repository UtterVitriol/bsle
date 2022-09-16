/** @file accounts.h
 *
 * @brief Login, add, delete or validate users.
 *
 * @par
 * COPYRIGHT NOTICE: (c) 2022 U.S. Army. All rights reserved. This software is
 * placed in the public domain and may be used for any purpose, as long as that
 * purpose is in service of the United States Army. HOOAH! However, this notice
 * must not be changed or removed. No warranty is expressed or implied by the
 * publication or distribution of this source code.
 */

#ifndef ACCOUNTS_H
#define ACCOUNTS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "ftp_lib.h"
#include "hash_table.h"

typedef struct User_Account
{
    char   *p_username;
    size_t  username_len;
    char   *p_password;
    size_t  password_len;
    uint8_t auth_level;
} User_Account;

int client_login(Account_Request *p_request, Table *p_accounts);

int delete_account(Account_Request *p_request, Table *p_accounts);

int add_account(Account_Request *p_request, Table *p_accounts);

User_Account *create_account(Account_Request *p_request);

int validate_user(User_Account *account, Table *p_accounts);

int username_comp(void *p_incoming, void *p_stored);

int password_comp(User_Account *p_incoming, User_Account *p_stored);

size_t hash_username(void *p_account, size_t size);

int free_account(void *p_data);

#endif /* ACCOUNTS_H */

/*** end of file ***/