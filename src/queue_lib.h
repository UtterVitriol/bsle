/** @file queue_lib.h
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

#ifndef QUEUE_LIB_H
#define QUEUE_LIB_H

#include <stdio.h>

typedef struct Queue
{
    size_t head;
    void **pp_queue;
    size_t tail;
    size_t capacity;
    size_t size;
} Queue;

Queue *queue_create(size_t capacity);

int queue_destroy(Queue **pp_queue);

int queue_enqueue(Queue *p_queue, void *p_data);

void *queue_dequeue(Queue *p_queue);

void *queue_search(Queue *p_queue,
                   void  *p_key,
                   int (*p_comp)(void *p_key, void *p_val));

#endif /* QUEUE_LIB_H */

/*** end of file ***/
