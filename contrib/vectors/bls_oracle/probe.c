/*
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

/*
 * Dash Core BLS oracle probe: forwards requests to the BLS entry points of the
 * Dash Core consensus oracle (libdash_oracle, ABI 14) and prints Core's
 * answers, one line per request.
 *
 * Requests (stdin), hex arguments:
 *   I                                  -> <abi> <core version>
 *   X <script>                         -> <ret> <records>    oracle_bls_exec
 *   D <kind> <mode> <legacy> <in>      -> <ret> <valid> <out> oracle_bls_decode
 * An empty byte string prints as "-"; a failed call also prints Core's message
 * after a tab.
 */

#define _POSIX_C_SOURCE 200809L

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/* The archive's entry points carry its pin's prefix (build-oracle.sh). */
#ifndef ORACLE_PREFIX
#define ORACLE_PREFIX oracle_v24_0_
#endif
#define CAT2(a, b) a##b
#define CAT(a, b) CAT2(a, b)
#define FN(name) CAT(ORACLE_PREFIX, name)

int FN(abi_version)(void);
const char* FN(core_version)(void);
size_t FN(last_error)(char* out, size_t cap);
int FN(bls_exec)(const uint8_t* script, size_t script_len, uint8_t* out, size_t* out_len);
int FN(bls_decode)(int kind, int mode, int legacy, const uint8_t* in, size_t in_len, int* valid, uint8_t* reser,
                   size_t* reser_len);

#define ORACLE_E_BUFFER (-3)

static void die(const char* what)
{
    fprintf(stderr, "probe: %s\n", what);
    exit(2);
}

static int nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    die("bad hex digit");
    return 0;
}

/* Decode a hex token ("-" is empty) into a fresh buffer. */
static uint8_t* unhex(const char* tok, size_t* len)
{
    if (tok == NULL) die("missing argument");
    if (strcmp(tok, "-") == 0) tok = "";
    size_t n = strlen(tok);
    if (n % 2 != 0) die("odd hex length");
    uint8_t* out = malloc(n / 2 + 1);
    if (out == NULL) die("out of memory");
    for (size_t i = 0; i < n / 2; i++) out[i] = (uint8_t)(nibble(tok[2 * i]) << 4 | nibble(tok[2 * i + 1]));
    *len = n / 2;
    return out;
}

/* Decode a hex token that must hold exactly len bytes. */
static void put_hex(const uint8_t* bytes, size_t len)
{
    if (len == 0) {
        fputs("-", stdout);
        return;
    }
    for (size_t i = 0; i < len; i++) printf("%02x", bytes[i]);
}

static void put_error(int ret)
{
    if (ret >= 0) return;
    char msg[512];
    FN(last_error)(msg, sizeof msg);
    msg[sizeof msg - 1] = '\0';
    for (char* p = msg; *p != '\0'; p++) {
        if (*p == '\t' || *p == '\n') *p = ' ';
    }
    printf("\t%s", msg);
}

static int to_int(const char* tok)
{
    if (tok == NULL) die("missing argument");
    return atoi(tok);
}

/* oracle_bls_exec, growing the output buffer when Core asks for more. */
static void request_exec(char* save)
{
    size_t in_len;
    uint8_t* in = unhex(strtok_r(NULL, " ", &save), &in_len);
    size_t cap = 4096;
    uint8_t* out = NULL;
    size_t out_len;
    int ret;
    do {
        free(out);
        out = malloc(cap);
        if (out == NULL) die("out of memory");
        out_len = cap;
        ret = FN(bls_exec)(in, in_len, out, &out_len);
        cap = out_len;
    } while (ret == ORACLE_E_BUFFER);
    printf("%d ", ret);
    put_hex(out, ret >= 0 ? out_len : 0);
    put_error(ret);
    free(in);
    free(out);
}

static void request_decode(char* save)
{
    const int kind = to_int(strtok_r(NULL, " ", &save));
    const int mode = to_int(strtok_r(NULL, " ", &save));
    const int legacy = to_int(strtok_r(NULL, " ", &save));
    size_t in_len;
    uint8_t* in = unhex(strtok_r(NULL, " ", &save), &in_len);
    uint8_t out[96];
    size_t out_len = sizeof out;
    int valid = 0;
    const int ret = FN(bls_decode)(kind, mode, legacy, in, in_len, &valid, out, &out_len);
    printf("%d %d ", ret, valid);
    put_hex(out, ret == 0 ? out_len : 0);
    put_error(ret);
    free(in);
}

int main(void)
{
    char* line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, stdin)) > 0) {
        if (line[n - 1] == '\n') line[n - 1] = '\0';
        char* save = NULL;
        const char* cmd = strtok_r(line, " ", &save);
        if (cmd == NULL) continue;
        if (strcmp(cmd, "I") == 0) {
            printf("%d %s", FN(abi_version)(), FN(core_version)());
        } else if (strcmp(cmd, "X") == 0) {
            request_exec(save);
        } else if (strcmp(cmd, "D") == 0) {
            request_decode(save);
        } else {
            die("unknown request");
        }
        putchar('\n');
        fflush(stdout);
    }
    free(line);
    return 0;
}
