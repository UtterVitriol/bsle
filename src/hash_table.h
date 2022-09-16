/** @file hash_table.h
 *
 * @brief Hash table.
 *
 * @par
 * COPYRIGHT NOTICE: (c) 2022 U.S. Army. All rights reserved. This software is
 * placed in the public domain and may be used for any purpose, as long as that
 * purpose is in service of the United States Army. HOOAH! However, this notice
 * must not be changed or removed. No warranty is expressed or implied by the
 * publication or distribution of this source code.
 */

#ifndef HASH_TABLE_H
#define HASH_TABLE_H

/**
 * \file hash_table.h
 * \brief Create and manipulate a hash table
 */

#include <stdio.h>
#include <stdlib.h>

/**
 * \def Bucket
 * \brief Hash collision mitigation
 */
typedef struct Bucket
{
    void          *p_data;
    size_t         size;
    size_t         key;
    struct Bucket *p_next;
    struct Bucket *p_prev;
} Bucket;

/**
 * \def Table
 * \brief Hash table
 */
typedef struct Table
{
    Bucket **pp_buckets;
    size_t   size;
    size_t   count;
    int (*p_data_cleanup)(void *p_data);
} Table;

Table *init_table(size_t size, int (*pp_data_cleanup)(void *pp_data));

int destroy_table(Table **pp_table);

int insert_table(Table *p_table,
                 void  *p_data,
                 size_t size,
                 int (*p_comp)(void *p_left, void *p_right),
                 size_t (*p_hash)(void *p_data, size_t size));

void *search_table(Table *p_table,
                   void  *p_data,
                   size_t size,
                   int (*p_comp)(void *p_left, void *p_right),
                   size_t (*p_hash)(void *p_data, size_t size));

int delete_from_table(Table *p_table,
                      void  *p_data,
                      size_t size,
                      int (*p_comp)(void *p_left, void *p_right),
                      size_t (*p_hash)(void *p_data, size_t size));

#endif /* HASH_TABLE_H */

/*** end of file ***/
