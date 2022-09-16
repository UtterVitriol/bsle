/** @file accounts.c
 *
 * @brief Login, add, delete or validate users. This is just an interface with
 * the hash table.
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

#include "accounts.h"
#include "hash_table.h"
#include "ftp_lib.h"

/**
 * @brief Client login.
 *
 * @param[in] p_request Login request.
 * @param[in] p_accounts Accounts.
 *
 * @return Authentication level on success, otherwise -1.
 */
int
client_login(Account_Request *p_request, Table *p_accounts)
{

    int ret = FAILURE;

    if (!p_request || !p_accounts)
    {
        fprintf(stderr, "Client_login Error: NULL ptr\n");
        goto END;
    }

    User_Account *p_account = NULL;

    p_account = create_account(p_request);

    if (!p_account)
    {
        ret = -1;
        goto END;
    }

    ret = validate_user(p_account, p_accounts);

    free_account(p_account);
END:

    return ret;
}

/**
 * @brief Delete account from hash table.
 *
 * @param p_request Account delete request.
 * @param p_accounts Accounts.
 *
 * @return 1 on success, 0 if not found, otherwise -1.
 */
int
delete_account(Account_Request *p_request, Table *p_accounts)
{
    int ret = -1;

    if (!p_request || !p_accounts)
    {
        fprintf(stderr, "Delete_account Error: NULL ptr\n");
        goto END;
    }

    User_Account *p_to_delete = NULL;

    p_to_delete = create_account(p_request);

    if (!p_to_delete)
    {
        goto END;
    }

    ret = delete_from_table(p_accounts,
                            p_to_delete,
                            p_to_delete->username_len,
                            username_comp,
                            hash_username);

    free_account(p_to_delete);

END:
    return ret;
}

/**
 * @brief Add account to hash table.
 *
 * @param p_request Add account request.
 * @param p_accounts Accounts.
 *
 * @return 0 on succes, 1 if already exists, otherwise -1.
 */
int
add_account(Account_Request *p_request, Table *p_accounts)
{
    int ret = -1;

    if (!p_request || !p_accounts)
    {
        fprintf(stderr, "Add_account Error: NULL ptr\n");
        goto END;
    }

    User_Account *p_account = NULL;

    p_account = create_account(p_request);

    if (!p_account)
    {
        goto END;
    }

    ret = insert_table(p_accounts,
                       p_account,
                       p_account->username_len,
                       username_comp,
                       hash_username);

END:
    return ret;
}

/**
 * @brief Create a account from request.
 *
 * @param p_request Create account request.
 *
 * @return User account on success, otherwise NULL.
 */
User_Account *
create_account(Account_Request *p_request)
{

    if (!p_request)
    {
        fprintf(stderr, "Create_account Error: NULL ptr\n");
        return NULL;
    }

    User_Account *p_account = NULL;

    p_account = calloc(1, sizeof(*p_account));

    if (!p_account)
    {
        fprintf(stderr, "Create_account Error: Calloc\n");
        return NULL;
    }

    p_account->p_username = calloc(1, p_request->name_len + 1);

    if (!p_account->p_username)
    {
        fprintf(stderr, "Create_account Error: Calloc\n");
        free(p_account);
        return NULL;
    }

    // Populate account username from request.
    //
    memcpy(
        p_account->p_username, p_request->p_credentials, p_request->name_len);

    p_account->username_len = p_request->name_len;

    p_account->p_password = calloc(1, p_request->password_len + 1);

    if (!p_account->p_password)
    {
        fprintf(stderr, "Create_account Error: Calloc\n");
        free(p_account->p_username);
        free(p_account);
        return NULL;
    }

    // Populate account password from request.
    //
    memcpy(p_account->p_password,
           (p_request->p_credentials + p_request->name_len),
           p_request->password_len);

    p_account->password_len = p_request->password_len;

    p_account->auth_level = p_request->flag;

    return p_account;
}

/**
 * @brief Compare request username to stored username.
 *
 * @param p_incoming Username of requestor.
 * @param p_stored Username stored in hash table.
 *
 * @return 0 if match, otherwise a positive or negative number.
 */
int
username_comp(void *p_incoming, void *p_stored)
{
    return strcmp(((User_Account *)p_incoming)->p_username,
                  ((User_Account *)p_stored)->p_username);
}

/**
 * @brief Compare request password to stored password.
 *
 * @param p_incoming Password of requestor.
 * @param p_stored  Password stored in hash table.
 * @return 0 if match, otherwise a positive or negative number.
 */
int
password_comp(User_Account *p_incoming, User_Account *p_stored)
{
    return strncmp(
        p_stored->p_password, p_incoming->p_password, p_incoming->password_len);
}

/**
 * @brief Hash username.
 *
 * @param p_account Account that has username to hash.
 * @param size Length of username.
 *
 * @return Hash of username.
 */
size_t
hash_username(void *p_account, size_t size)
{
    // This based on: djb2 hash
    // Name: Dan Bernstein
    // Location: http://www.cse.yorku.ca/~oz/hash.html

    unsigned long hash = 5381;
    int           c;

    void  *p_byte_ptr = ((User_Account *)p_account)->p_username;
    size_t count      = 0;

    while (count != size)
    {
        c = *(char *)p_byte_ptr;

        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

        p_byte_ptr = (char *)p_byte_ptr + 1;
        count++;
    }
    return hash;
}

/**
 * @brief Free's account.
 *
 * @param p_data Account.
 *
 * @return 0 on success, otherwise -1.
 */
int
free_account(void *p_data)
{

    if (!p_data)
    {
        fprintf(stderr, "Free_account Error: NULL ptr\n");
        return -1;
    }

    User_Account *p_account = (User_Account *)p_data;

    if (!p_account->p_username || !p_account->p_password)
    {
        fprintf(stderr, "Free_account Error: NULL ptr\n");
        return -1;
    }

    free(p_account->p_username);
    free(p_account->p_password);

    free(p_account);

    return 0;
}

/**
 * @brief Validate user.
 *
 * @param p_to_validate User to validate.
 * @param p_accounts Accounts.
 *
 * @return Authentication level on success, otherwise -1.
 */
int
validate_user(User_Account *p_to_validate, Table *p_accounts)
{
    int auth_level = -1;

    if (p_to_validate->password_len < 1)
    {
        goto END;
    }

    User_Account *p_existing_account = NULL;

    p_existing_account = search_table(p_accounts,
                                      p_to_validate,
                                      p_to_validate->username_len,
                                      username_comp,
                                      hash_username);

    if (p_existing_account)
    {
        if (password_comp(p_to_validate, p_existing_account) == 0)
        {
            auth_level = p_existing_account->auth_level;
        }
    }

END:
    return auth_level;
}

/*** end of file ***/