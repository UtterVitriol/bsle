/** @file thread_pool.h
 *
 * @brief Thread pool.
 *
 * @par
 * COPYRIGHT NOTICE: (c) 2022 U.S. Army. All rights reserved. This software is
 * placed in the public domain and may be used for any purpose, as long as that
 * purpose is in service of the United States Army. HOOAH! However, this notice
 * must not be changed or removed. No warranty is expressed or implied by the
 * publication or distribution of this source code.
 */

#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <pthread.h>

#include "queue_lib.h"

typedef struct __task
{
    int (*p_funciton)(void *);
    void *p_arg;
} Task;

typedef struct __thread_pool
{
    pthread_mutex_t lock;
    pthread_cond_t  cond;
    pthread_t      *p_threads;
    Queue          *p_jobs;
    int             b_shutdown;
    size_t          capacity;
    size_t          running;
} Thread_Pool;

Thread_Pool *init_pool(size_t thread_num, size_t job_num);

int destroy_pool(Thread_Pool **pp_pool);

int add_job(Thread_Pool *p_pool, int (*p_func)(void *), void *p_arg);

void *thread(void *p_thread_pool_ptr);

#endif /* THREAD_POOL_H */

/*** end of file ***/
