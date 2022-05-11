#ifndef ROCCA_H
#define ROCCA_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "../src/rocca_u128.h"

enum {
    // ROCCA_KEY_SIZE is the size in bytes of a Rocca key.
    ROCCA_KEY_SIZE = 32,
    // ROCCA_NONCE_SIZE is the size in bytes of a Rocca nonce.
    ROCCA_NONCE_SIZE = 16,
    // ROCCA_TAG_SIZE is the size in bytes of a Rocca tag.
    ROCCA_TAG_SIZE = 16,
    // ROCCA_OVERHEAD is the size difference in bytes between
    // a plaintext and its ciphertext.
    ROCCA_OVERHEAD = ROCCA_TAG_SIZE,
};

typedef u128 rocca_state[8];

// Z0: A constant block defined as Z0 = 428a2f98d728ae227137449123ef65cd.
static const uint8_t Z0[16] = {
    0xcd, 0x65, 0xef, 0x23, 0x91, 0x44, 0x37, 0x71,
    0x22, 0xae, 0x28, 0xd7, 0x98, 0x2f, 0x8a, 0x42,
};

// Z1: A constant block defined as Z1 = b5c0fbcfec4d3b2fe9b5dba58189dbbc.
static const uint8_t Z1[16] = {
    0xbc, 0xdb, 0x89, 0x81, 0xa5, 0xdb, 0xb5, 0xe9,
    0x2f, 0x3b, 0x4d, 0xec, 0xcf, 0xfb, 0xc0, 0xb5,
};

u128 rocca_mac(rocca_state s, uint64_t additional_data_len, uint64_t plaintext_len);

void rocca_update(rocca_state s, u128 x0, u128 x1);
void rocca_downdate(rocca_state s, u128 x0, u128 x1);

void rocca_init(rocca_state s, const uint8_t key[ROCCA_KEY_SIZE], const uint8_t nonce[ROCCA_NONCE_SIZE]);

// rocca_seal encrypts and authenticates |plaintext_len| bytes
// from |plaintext|, authenticates |additional_data_len| bytes
// from |additional_data|, and writes the result to |dst|.
//
// It returns true on success and false otherwise.
//
// |dst_len| must be at least |plaintext_len| + |ROCCA_OVERHEAD|
// bytes long.
//
// The length of |key|, |key_len|, must be exactly
// |ROCCA_KEY_SIZE| bytes long.
//
// The length of |nonce|, |nonce_len|, must be exactly
// |ROCCA_NONCE_SIZE| bytes long. It is important to ensure that
// |nonce| is forever unique for each |key|. In other words, it
// is a catastrophic error to EVER repeat a (|nonce|, |key|)
// pair.
//
// If |plaintext| is NULL, |plaintext_len| must be zero.
// Similarly, if |plaintext_len| is zero, |plaintext| must be
// NULL.
//
// If |additional_data| is NULL, |additional_data_len| must be
// zero. Similarly, if |additional_data_len| is zero,
// |additional_data| must be NULL.
//
// |rocca_seal| never returns partial output: if it returns
// false, |dst_len| bytes of |dst| will be filled with zeros.
bool rocca_seal(uint8_t* dst,
                size_t dst_len,
                const uint8_t key[ROCCA_KEY_SIZE],
                size_t key_len,
                const uint8_t nonce[ROCCA_NONCE_SIZE],
                size_t nonce_len,
                const uint8_t* plaintext,
                size_t plaintext_len,
                const uint8_t* additional_data,
                size_t additional_data_len);

// rocca_open decrypts and authenticates |ciphertext_len| bytes
// from |ciphertext|, authenticates |additional_data_len| bytes
// from |additional_data|, and writes the result to |dst|.
//
// It returns true on success and false otherwise.
//
// |ciphertext_len| must be at least |ROCCA_OVERHEAD| bytes long.
//
// |dst_len| must be at least |ciphertext_len| - |ROCCA_OVERHEAD|
// bytes long.
//
// The length of |key|, |key_len|, must be exactly
// |ROCCA_KEY_SIZE| bytes long.
//
// If |additional_data| is NULL, |additional_data_len| must be
// zero. Similarly, if |additional_data_len| is zero,
// |additional_data| must be NULL.
//
// |rocca_open| never returns partial output: if it returns
// false, |dst_len| bytes of |dst| will be filled with zeros.
bool rocca_open(uint8_t* dst,
                size_t dst_len,
                const uint8_t key[ROCCA_KEY_SIZE],
                size_t key_len,
                const uint8_t nonce[ROCCA_NONCE_SIZE],
                size_t nonce_len,
                const uint8_t* ciphertext,
                size_t ciphertext_len,
                const uint8_t* additional_data,
                size_t additional_data_len);

#endif // ROCCA_H
