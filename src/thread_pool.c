/** @file thread_pool.c
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

// Code based on:
// https://programmer.group/c-simple-thread-pool-based-on-pthread-implementation.html

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "thread_pool.h"
#include "queue_lib.h"

/**
 * @brief Allocates thread pool
 *
 * @param thr_num Number of threads.
 * @param job_num Number of jobs.
 *
 * @return Alloc'd thread pool on success, otherwise NULL;
 */
Thread_Pool *
init_pool(size_t thread_num, size_t job_num)
{

    Thread_Pool *p_new_pool = NULL;

    p_new_pool = calloc(1, sizeof(*p_new_pool));

    if (!p_new_pool)
    {
        fprintf(stderr, "Init_pool Error: Calloc (pool)\n");
        return NULL;
    }

    if (pthread_mutex_init(&p_new_pool->lock, NULL) != 0)
    {
        fprintf(stderr, "Init_pool Error: pthread_mutex_init\n");
        free(p_new_pool);
        return NULL;
    }

    if (pthread_cond_init(&p_new_pool->cond, NULL) != 0)
    {
        fprintf(stderr, "Init_pool Error: pthread_cond_init\n");
        destroy_pool(&p_new_pool);
        free(p_new_pool);
        return NULL;
    }

    p_new_pool->capacity = thread_num;

    p_new_pool->p_threads
        = calloc(p_new_pool->capacity, sizeof(p_new_pool->p_threads));

    if (!p_new_pool->p_threads)
    {
        fprintf(stderr, "Init_pool Error: calloc (threads)\n");
        destroy_pool(&p_new_pool);
        return NULL;
    }

    p_new_pool->p_jobs = queue_create(job_num);

    if (!p_new_pool->p_jobs)
    {
        fprintf(stderr, "Init_pool Error: queue_create (jobs)\n");
        destroy_pool(&p_new_pool);
        return NULL;
    }

    for (size_t thr = 0; thr < p_new_pool->capacity; thr++)
    {
        if (pthread_create(
                &p_new_pool->p_threads[thr], NULL, thread, (void *)p_new_pool)
            != 0)
        {
            fprintf(stderr, "Init_pool Error: pthread_create\n");
            destroy_pool(&p_new_pool);
            return NULL;
        }

        p_new_pool->running++;
    }

    return p_new_pool;
}

/**
 * @brief Free's thread pool.
 *
 * @param pp_pool Thread pool.
 *
 * @return 0 on succcess, otherwise -1.
 */
int
destroy_pool(Thread_Pool **pp_pool)
{
    int ret = 0;
    if (!pp_pool || !*pp_pool)
    {
        fprintf(stderr, "Destroy_pool Error: NULL ptr\n");
        return -1;
    }

    Thread_Pool *p_pool = *pp_pool;

    if (!p_pool->p_threads)
    {
        fprintf(stderr, "Destroy_pool Error: Threads ptr is NULL\n");
        ret = -1;
        goto END;
    }

    if (!p_pool->p_jobs)
    {
        fprintf(stderr, "Destroy_pool Error: Queue is NULL\n");
        ret = -1;
        goto END;
    }

    // Allows threads to finish current job.
    //
    if (pthread_mutex_lock(&p_pool->lock) != 0)
    {
        fprintf(stderr, "Destroy_pool : Lock failure\n");
        ret = -1;
        goto END;
    }

    // Tell threads to shut down.
    //
    p_pool->b_shutdown = 1;

    if (pthread_cond_broadcast(&p_pool->cond) != 0)
    {
        fprintf(stderr, "Destroy_pool Error: Thread broacast failure\n");
        ret = -1;
        goto END;
    }

    if (pthread_mutex_unlock(&p_pool->lock) != 0)
    {
        fprintf(stderr, "Destroy_pool Error: Thread unlock failure\n");
        ret = -1;
        goto END;
    }

    for (size_t thread = 0; thread < p_pool->capacity; thread++)
    {
        if (pthread_join(p_pool->p_threads[thread], NULL) != 0)
        {
            fprintf(stderr, "Destroy_pool Error: pthread_join\n");
            ret = -1;
        }
    }

    free(p_pool->p_threads);

    size_t pos = p_pool->p_jobs->head;

    ret = queue_destroy(&p_pool->p_jobs);

    if (pthread_mutex_destroy(&p_pool->lock) != 0)
    {
        fprintf(stderr, "Destroy_pool Error: mutex_destroy\n");
        ret = -1;
    }

    if (pthread_cond_destroy(&p_pool->cond) != 0)
    {
        fprintf(stderr, "Destroy_pool error: cond destroy\n");
        ret = -1;
    }

    free(p_pool);

    *pp_pool = NULL;

END:
    return ret;
}

/**
 * @brief Add job to thread pool.
 *
 * @param p_pool Thread pool.
 * @param p_func Function of job.
 * @param p_arg Argument for job.
 *
 * @return 0 on success, otherwise -1.
 */
int
add_job(Thread_Pool *p_pool, int (*p_func)(void *), void *p_arg)
{
    int   ret    = 0;
    Task *p_task = NULL;

    if (!p_pool || !p_func || !p_arg)
    {
        fprintf(stderr, "Add_job Error: NULL ptr\n");
        ret = -1;
        goto END;
    }

    if (pthread_mutex_lock(&p_pool->lock) != 0)
    {
        fprintf(stderr, "Add_job Error: Lock failure\n");
        exit(1);
    }

    if (p_pool->p_jobs->size == p_pool->p_jobs->capacity)
    {
        fprintf(stderr, "Add_Job Error: Job queue full\n");
        ret = 1;
        goto END;
    }

    if (p_pool->b_shutdown)
    {
        ret = -1;
        goto END;
    }

    p_task = calloc(1, sizeof(*p_task));

    if (!p_task)
    {
        fprintf(stderr, "Add_job Error: Calloc\n");
        ret = -1;
        goto END;
    }

    p_task->p_funciton = p_func;
    p_task->p_arg      = p_arg;

    if (queue_enqueue(p_pool->p_jobs, p_task) != 0)
    {
        free(p_task);
        ret = -1;
        goto END;
    }

    if (pthread_cond_signal(&p_pool->cond) != 0)
    {
        fprintf(stderr, "Add_job Error: Cond failure\n");
        exit(1);
    }

END:
    if (pthread_mutex_unlock(&p_pool->lock) != 0)
    {
        fprintf(stderr, "Add_job Error: Unlock failure\n");
        exit(1);
    }
    return ret;
}

/**
 * @brief Thread.
 *
 * @param p_thread_pool Thread pool.
 *
 * @return Not sure why this exists. NULL.
 */
void *
thread(void *p_thread_pool)
{
    // Use exit(1) here for cleanup becuase I was not able to come up with
    // a simple solution. But, the chances of it actually happening are small.
    //
    Thread_Pool *p_pool   = (Thread_Pool *)p_thread_pool;
    Task        *p_task   = NULL;
    pthread_t   *p_thread = NULL;

    for (;;)
    {

        if (pthread_mutex_lock(&p_pool->lock) != 0)
        {
            fprintf(stderr, "Thread Error: Lock\n");
            exit(1);
        }

        while ((0 == p_pool->p_jobs->size) && (!p_pool->b_shutdown))
        {
            // Wait for queue
            //
            if (pthread_cond_wait(&p_pool->cond, &p_pool->lock) != 0)
            {
                fprintf(stderr, "Thread Error: cond_wait\n");
                exit(1);
            }
        }

        if (p_pool->b_shutdown)
        {
            break;
        }

        p_task = queue_dequeue(p_pool->p_jobs);

        if (!p_task)
        {
            fprintf(stderr, "Thread Error: dequeue\n");
            if (pthread_mutex_lock(&p_pool->lock) != 0)
            {
                fprintf(stderr, "Thread Error: Lock\n");
                exit(1);
            }
            continue;
        }

        if (pthread_mutex_unlock(&p_pool->lock) != 0)
        {
            fprintf(stderr, "Thread Error: unlock\n");
            exit(1);
        }

        p_task->p_funciton(p_task->p_arg);

        free(p_task);
    }

    p_pool->running--;

    if (pthread_mutex_unlock(&p_pool->lock) != 0)
    {
        fprintf(stderr, "Thread Error: unlock\n");
        exit(1);
    }

    return NULL;
}

/*** end of file ***/
