/*
 * Copyright (c) 2011-2012 Hunter Morris <hunter.morris@smarkets.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "erl_nif.h"
#include "erl_blf.h"
#include "bcrypt_nif.h"

void free_task(task_t* task)
{
    if (task->env != NULL)
        enif_free_env(task->env);
    enif_free(task);
}

task_t* alloc_task(task_type_t type)
{
    task_t* task = (task_t*)enif_alloc(sizeof(task_t));
    if (task == NULL)
        return NULL;
    (void)memset(task, 0, sizeof(task_t));
    task->type = type;
    return task;
}

task_t* alloc_init_task(task_type_t type, ERL_NIF_TERM ref)
{
    task_t* task = alloc_task(type);
    task->env = enif_alloc_env();
    if (task->env == NULL) {
        free_task(task);
        return NULL;
    }

    task->ref = enif_make_copy(task->env, ref);
    return task;
}

static ERL_NIF_TERM hashpw(task_t* task)
{
    char password[1024] = { 0 };
    char salt[1024] = { 0 };
    char *ret = NULL;

    size_t password_sz = 1024;
    if (password_sz > task->data.hash.password.size)
        password_sz = task->data.hash.password.size;
    (void)memcpy(&password, task->data.hash.password.data, password_sz);

    size_t salt_sz = 1024;
    if (salt_sz > task->data.hash.salt.size)
        salt_sz = task->data.hash.salt.size;
    (void)memcpy(&salt, task->data.hash.salt.data, salt_sz);

    if (NULL == (ret = bcrypt(password, salt)) || 0 == strcmp(ret, ":")) {
        return enif_make_tuple3(
            task->env,
            enif_make_atom(task->env, "error"),
            task->ref,
            enif_make_string(task->env, "bcrypt failed", ERL_NIF_LATIN1));
    }

    return enif_make_tuple3(
        task->env,
        enif_make_atom(task->env, "ok"),
        task->ref,
        enif_make_string(task->env, ret, ERL_NIF_LATIN1));
}

void* async_worker(void* arg)
{
    ctx_t* ctx;
    task_t* task;

    ERL_NIF_TERM result;

    ctx = (ctx_t*)arg;

    while (1) {
        task = (task_t*)async_queue_pop(ctx->queue);

        if (task->type == SHUTDOWN) {
            break;
        } else if (task->type == HASH) {
            result = hashpw(task);
        } else {
            errx(1, "Unexpected task type: %i", task->type);
        }

        enif_send(NULL, &task->pid, task->env, result);
        free_task(task);
    }

    // Cleanup the shutdown task
    free_task(task);
    return NULL;
}

static ERL_NIF_TERM bcrypt_encode_salt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary csalt, bin;
    unsigned long log_rounds;

    if (!enif_inspect_binary(env, argv[0], &csalt) || 16 != csalt.size) {
        return enif_make_badarg(env);
    }

    if (!enif_get_ulong(env, argv[1], &log_rounds)) {
        enif_release_binary(&csalt);
        return enif_make_badarg(env);
    }

    if (!enif_alloc_binary(64, &bin)) {
        enif_release_binary(&csalt);
        return enif_make_badarg(env);
    }

    encode_salt((char *)bin.data, (u_int8_t*)csalt.data, csalt.size, log_rounds);
    enif_release_binary(&csalt);

    return enif_make_string(env, (char *)bin.data, ERL_NIF_LATIN1);
}

static ERL_NIF_TERM bcrypt_hashpw(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    char pw[1024];
    char salt[1024];
    char *ret = NULL;

    (void)memset(&pw, '\0', sizeof(pw));
    (void)memset(&salt, '\0', sizeof(salt));

    if (enif_get_string(env, argv[0], pw, sizeof(pw), ERL_NIF_LATIN1) < 1)
        return enif_make_badarg(env);

    if (enif_get_string(env, argv[1], salt, sizeof(salt), ERL_NIF_LATIN1) < 1)
        return enif_make_badarg(env);

    if (NULL == (ret = bcrypt(pw, salt)) || 0 == strcmp(ret, ":")) {
        return enif_make_badarg(env);
    }

    return enif_make_string(env, ret, ERL_NIF_LATIN1);
}

static ERL_NIF_TERM bcrypt_create_ctx(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM ret;
    bcrypt_privdata_t *priv = (bcrypt_privdata_t*)enif_priv_data(env);
    ctx_t* ctx = (ctx_t*)enif_alloc_resource(priv->bcrypt_rt, sizeof(ctx_t));
    if (ctx == NULL)
        return enif_make_badarg(env);
    ctx->queue = async_queue_create();
    ctx->topts = enif_thread_opts_create("bcrypt_thread_opts");
    if (enif_thread_create("bcrypt_worker", &ctx->tid, async_worker, ctx, ctx->topts) != 0) {
        enif_release_resource(ctx);
        return enif_make_badarg(env);
    }
    ret = enif_make_resource(env, ctx);
    enif_release_resource(ctx);
    return ret;
}

static ErlNifFunc bcrypt_nif_funcs[] =
{
    {"encode_salt", 2, bcrypt_encode_salt},
    {"hashpw", 2, bcrypt_hashpw},
    {"create_ctx", 0, bcrypt_create_ctx},
};

static void bcrypt_rt_dtor(ErlNifEnv* env, void* obj)
{
    ctx_t  *ctx = (ctx_t*)obj;
    task_t *task = alloc_task(SHUTDOWN);
    void   *result = NULL;

    async_queue_push(ctx->queue, (void*)task);
    enif_thread_join(ctx->tid, &result);
    async_queue_destroy(ctx->queue);
    enif_thread_opts_destroy(ctx->topts);
}

static int on_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info)
{
    const char *mod = "bcrypt_nif";
    const char *name = "nif_resource";

    ErlNifResourceFlags flags = (ErlNifResourceFlags)(ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER);

    bcrypt_privdata_t *priv = (bcrypt_privdata_t*)enif_alloc(sizeof(bcrypt_privdata_t));
    priv->bcrypt_rt = enif_open_resource_type(env, mod, name, bcrypt_rt_dtor, flags, NULL);
    if (priv->bcrypt_rt == NULL)
        return -1;
    *priv_data = priv;
    return 0;
}

ERL_NIF_INIT(bcrypt_nif, bcrypt_nif_funcs, &on_load, NULL, NULL, NULL)
