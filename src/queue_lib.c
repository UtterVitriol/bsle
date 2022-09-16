/** @file queue_lib.c
 *
 * @brief Queue.
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
#include <stdbool.h>

#include "queue_lib.h"

// code based on
// https://www.geeksforgeeks.org/queue-set-1introduction-and-array-implementation/

/**
 * @brief Allocates queue.
 *
 * @param capacity Size of queue.
 *
 * @return Alloc'd queue on succcess, otherwise NULL.
 */
Queue *
queue_create(size_t capacity)
{
    Queue *p_new_queue = NULL;

    if (0 == capacity)
    {
        fprintf(stderr, "Queue_create Errro: capicity can't be 0\n");
        goto END;
    }

    p_new_queue = calloc(1, sizeof(*p_new_queue));

    if (!p_new_queue)
    {
        fprintf(stderr, "Queue_create Error: Calloc\n");
        goto END;
    }

    p_new_queue->pp_queue = calloc(capacity, sizeof(p_new_queue->pp_queue));

    if (!p_new_queue->pp_queue)
    {
        fprintf(stderr, "Queue_create Error: Calloc\n");
        free(p_new_queue);
        p_new_queue = NULL;
        goto END;
    }

    p_new_queue->capacity = capacity;
    p_new_queue->tail     = capacity - 1;

END:
    return p_new_queue;
}

/**
 * @brief Free's queue.
 *
 * @param pp_queue Queue.
 *
 * @return 0 on success, otherwise -1.
 */
int
queue_destroy(Queue **pp_queue)
{

    if (!pp_queue)
    {
        fprintf(stderr, "Queue_destroy Error: NULL ptr\n");
        return -1;
    }

    size_t j = (*pp_queue)->head;
    for (size_t i = 0; i < (*pp_queue)->size; i++)
    {
        free((*pp_queue)->pp_queue[j]);
        j = ((j + 1) % (*pp_queue)->capacity);
    }

    free((*pp_queue)->pp_queue);
    free(*pp_queue);
    *pp_queue = NULL;

    return 0;
}

/**
 * @brief Adds data to queue.
 *
 * @param p_queue Queue.
 * @param p_data Data.
 *
 * @return 0 on success, otherwise -1.
 */
int
queue_enqueue(Queue *p_queue, void *p_data)
{
    if (!p_queue || !p_data)
    {
        fprintf(stderr, "Queue_enqueue Error: NULL ptr\n");
        return -1;
    }

    if (p_queue->size == p_queue->capacity)
    {
        fprintf(stderr, "Queue_enqueue Error: Queue Full\n");
        return -1;
    }

    p_queue->tail                    = (p_queue->tail + 1) % p_queue->capacity;
    p_queue->pp_queue[p_queue->tail] = p_data;
    p_queue->size                    = p_queue->size + 1;

    return 0;
}

/**
 * @brief Get's head queueu.
 *
 * @param p_queue Queue.
 *
 * @return Head of queue on success, otherwise NULL.
 */
void *
queue_dequeue(Queue *p_queue)
{
    void *p_data = NULL;

    if (!p_queue)
    {
        fprintf(stderr, "Queue_destroy Error: NULL ptr\n");
        goto END;
    }

    if (p_queue->size != 0)
    {
        p_data        = p_queue->pp_queue[p_queue->head];
        p_queue->head = (p_queue->head + 1) % p_queue->capacity;
        p_queue->size = p_queue->size - 1;
    }
    else
    {
        fprintf(stderr, "Queue_dequeue Error: Queue Empty\n");
    }

END:
    return p_data;
}

/**
 * @brief Searches queue.
 *
 * @param p_queue Queue.
 * @param p_key Data to search for.
 * @param p_comp Comparison function.
 *
 * @return Data on success, otherwise -1.
 */
void *
queue_search(Queue *p_queue,
             void  *p_key,
             int (*p_comp)(void *p_key, void *p_val))
{
    void *p_found = NULL;

    if (!p_queue || !p_key || !p_comp)
    {
        fprintf(stderr, "Queue_search Error: NULL ptr\n");
        goto END;
    }

    if (0 == p_queue->size)
    {
        fprintf(stderr, "Queue_search Error: Queue Empty\n");
        goto END;
    }

    for (size_t i = 0; i < p_queue->size; i++)
    {
        if (p_comp(p_key, p_queue->pp_queue[i]) == 1)
        {
            p_found = p_queue->pp_queue[i];
            break;
        }
    }

END:
    return p_found;
}

/*** end of file ***/