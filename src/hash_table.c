/** @file hash_table.c
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

#include <stdio.h>
#include <stdlib.h>

#include "hash_table.h"

/**
 * @brief Allocates hash table.
 *
 * @param size Size of hash table.
 * @param p_data_cleanup Function to free data.
 *
 * @return Alloc'd hash table on success, otherwise NULL.
 */
Table *
init_table(size_t size, int (*p_data_cleanup)(void *p_data))
{
    if (0 == size)
    {
        fprintf(stderr, "Init_table Error: Size cannot be 0\n");
        return NULL;
    }

    if (!p_data_cleanup)
    {
        fprintf(stderr, "Init_table Error: NULL ptr\n");
        return NULL;
    }

    Table *p_new_table = NULL;

    p_new_table = calloc(1, sizeof(*p_new_table));

    if (!p_new_table)
    {
        fprintf(stderr, "Init_table Error: Calloc\n");
        return NULL;
    }

    p_new_table->pp_buckets = calloc(size, sizeof(*p_new_table->pp_buckets));

    if (!p_new_table->pp_buckets)
    {
        fprintf(stderr, "Init_table Error: Calloc\n");
        free(p_new_table);
        return NULL;
    }
    p_new_table->size  = size;
    p_new_table->count = 0;

    p_new_table->p_data_cleanup = p_data_cleanup;

    return p_new_table;
}

/**
 * @brief Free's hash table.
 *
 * @param pp_table Hash table.
 *
 * @return 0 on success, otherwise -1.
 */
int
destroy_table(Table **pp_table)
{
    if (!pp_table || !*pp_table)
    {
        fprintf(stderr, "Destroy_table Error: NULL ptr\n");
        return -1;
    }

    Bucket *p_bucket = NULL;
    Bucket *p_last   = NULL;

    for (size_t bucket = 0; bucket < (*pp_table)->size; bucket++)
        if ((*pp_table)->pp_buckets[bucket])
        {
            p_bucket = (*pp_table)->pp_buckets[bucket];

            // Go to end of list.
            //
            while (p_bucket->p_next)
            {
                p_bucket = p_bucket->p_next;
            }

            // Free nodes backwards.
            //
            while (p_bucket)
            {
                p_last = p_bucket->p_prev;
                (*pp_table)->p_data_cleanup(p_bucket->p_data);
                free(p_bucket);
                p_bucket = p_last;
            }
        }

    free((*pp_table)->pp_buckets);
    free(*pp_table);
    *pp_table = NULL;

    return 0;
}

/**
 * @brief Insert data into table.
 *
 * @param p_table Hash table.
 * @param p_data Data to be inserted.
 * @param size Size of data to compare.
 * @param p_comp Comparison function.
 * @param p_hash Hash function.
 *
 * @return 0 on success, 1 if exists, otherwise -1.
 */
int
insert_table(Table *p_table,
             void  *p_data,
             size_t size,
             int (*p_comp)(void *p_left, void *p_right),
             size_t (*p_hash)(void *p_data, size_t size))
{
    if (!p_table || !p_data || !p_comp || !p_hash)
    {
        fprintf(stderr, "Insert_table Error: NULL ptr\n");
        return -1;
    }

    Bucket *p_new_bucket = NULL;

    p_new_bucket = calloc(1, sizeof(*p_new_bucket));

    if (!p_new_bucket)
    {
        fprintf(stderr, "Insert_table Error: Calloc\n");
        return -1;
    }

    p_new_bucket->p_data = p_data;
    p_new_bucket->size   = size;
    p_new_bucket->key    = p_hash(p_new_bucket->p_data, p_new_bucket->size);
    p_new_bucket->p_next = NULL;
    p_new_bucket->p_prev = NULL;

    size_t pos = (p_new_bucket->key % p_table->size);

    Bucket *p_temp = NULL;

    // If nothing exists at index, add p_new_bucket bucket.
    //
    if (!p_table->pp_buckets[pos])
    {
        p_table->pp_buckets[pos] = p_new_bucket;
        p_table->count++;
        return 0;
    }

    // Get bucket at index to walk.
    //
    p_temp = p_table->pp_buckets[pos];

    // Walk down buckets.
    //
    while (p_temp->p_next)
    {
        // Key exists.
        //
        if (p_new_bucket->key == p_temp->key)
        {
            // p_data exists already.
            //
            if (p_comp(p_new_bucket->p_data, p_temp->p_data) == 0)
            {
                p_table->p_data_cleanup(p_new_bucket->p_data);
                free(p_new_bucket);
                return 1;
            }
        }
        p_temp = p_temp->p_next;
    }

    // Only one bucket at index.
    //
    if (p_comp(p_new_bucket->p_data, p_temp->p_data) == 0)
    {
        p_table->p_data_cleanup(p_new_bucket->p_data);
        free(p_new_bucket);
        return 1;
    }

    p_temp->p_next       = p_new_bucket;
    p_new_bucket->p_prev = p_temp;
    p_table->count++;
    return 0;
}

/**
 * @brief Search table for data.
 *
 * @param p_table Hash table.
 * @param p_data Data to search for.
 * @param size Size of data to compare.
 * @param p_comp Comparison function.
 * @param p_hash Hash function.
 * @return Pointer to bucket on success, otherwise NULL.
 */
void *
search_table(Table *p_table,
             void  *p_data,
             size_t size,
             int (*p_comp)(void *p_left, void *p_right),
             size_t (*p_hash)(void *p_data, size_t size))
{
    if (!p_table || !p_data || !p_comp || !p_hash)
    {
        fprintf(stderr, "Search_table Error: NULL ptr\n");
        return NULL;
    }

    size_t key = p_hash(p_data, size);

    size_t pos = (key % p_table->size);

    Bucket *p_bucket = p_table->pp_buckets[pos];

    if (p_bucket)
    {
        // Walk to linked list looking for key and data match.
        //
        while (p_bucket->p_next)
        {
            if (key == p_bucket->key)
            {
                if (p_comp(p_data, p_bucket->p_data) == 0)
                {
                    return p_bucket->p_data;
                }
            }

            p_bucket = p_bucket->p_next;
        }

        // Either one bucket or end of list.
        //
        if (key == p_bucket->key)
        {
            if (p_comp(p_data, p_bucket->p_data) == 0)
            {
                return p_bucket->p_data;
            }
        }
    }

    return NULL;
}

/**
 * @brief Delete data from table.
 *
 * @param p_table Hash table.
 * @param p_data Data to be deleted.
 * @param size Size of data to compare.
 * @param p_comp Comparison function.
 * @param p_hash Hash function.
 * @return 1 if found, 0 if not, otherwise -1.
 */
int
delete_from_table(Table *p_table,
                  void  *p_data,
                  size_t size,
                  int (*p_comp)(void *p_left, void *p_right),
                  size_t (*p_hash)(void *p_data, size_t size))
{
    if (!p_table || !p_data || !p_comp || !p_hash)
    {
        fprintf(stderr, "Delete_from_table Error: NULL ptr\n");
        return -1;
    }

    size_t key = p_hash(p_data, size);

    size_t pos = key % p_table->size;

    Bucket *p_bucket = p_table->pp_buckets[pos];

    if (p_bucket)
    {
        // Walk to linked list looking for key and data match.
        //
        while (p_bucket->p_next)
        {
            if (key == p_bucket->key)
            {
                if (p_comp(p_data, p_bucket->p_data) == 0)
                {
                    if (p_bucket->p_next)
                    {
                        p_bucket->p_prev->p_next = p_bucket->p_next;
                    }
                    else
                    {
                        p_bucket->p_prev->p_next = NULL;
                    }

                    p_table->p_data_cleanup(p_bucket->p_data);
                    free(p_bucket);
                    return 1;
                }
            }
            p_bucket = p_bucket->p_next;
        }

        // Either one bucket or end of list.
        //
        if (key == p_bucket->key)
        {
            if (p_comp(p_data, p_bucket->p_data) == 0)
            {
                if (p_bucket->p_next)
                {
                    p_table->pp_buckets[pos] = p_bucket->p_next;
                }
                else
                {
                    p_table->pp_buckets[pos] = NULL;
                }

                p_table->p_data_cleanup(p_bucket->p_data);
                free(p_bucket);
                return 1;
            }
        }
    }

    return 0;
}

/*** end of file ***/
