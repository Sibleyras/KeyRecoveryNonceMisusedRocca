// Rocca implementation by Eric Lagergen.

#include "rocca.h"

#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>

enum {
    // ROCCA_ROUNDS is the number of state update rounds performed by
    // |rocca_init| and |rocca_mac|.
    ROCCA_ROUNDS = 20,
    // ROCCA_BLOCK_SIZE is the size of one Rocca block.
    ROCCA_BLOCK_SIZE = 32,
};

void rocca_update(rocca_state s, u128 x0, u128 x1) {
    u128 t0 = xor_u128(s[7], x0);    // Snew[0] = S[7] ⊕ X0
    u128 t1 = aes_round(s[0], s[7]); // Snew[1] = AES(S[0], S[7])
    u128 t2 = xor_u128(s[1], s[6]);  // Snew[2] = S[1] ⊕ S[6]
    u128 t3 = aes_round(s[2], s[1]); // Snew[3] = AES(S[2], S[1])
    u128 t4 = xor_u128(s[3], x1);    // Snew[4] = S[3] ⊕ X1
    u128 t5 = aes_round(s[4], s[3]); // Snew[5] = AES(S[4], S[3])
    u128 t6 = aes_round(s[5], s[4]); // Snew[6] = AES(S[5], S[4])
    u128 t7 = xor_u128(s[0], s[6]);  // Snew[7] = S[0] ⊕ S[6]

    s[0] = t0;
    s[1] = t1;
    s[2] = t2;
    s[3] = t3;
    s[4] = t4;
    s[5] = t5;
    s[6] = t6;
    s[7] = t7;
}

void rocca_downdate(rocca_state s, u128 x0, u128 x1) {
    u128 t7 = xor_u128(s[0], x0);       // Sold[7] = S[0] ⊕ X0
    u128 t3 = xor_u128(s[4], x1);       // Sold[3] = S[4] ⊕ X1
    u128 t0 = aes_inv_round(s[1], t7);  // Sold[0] = AES_INV(S[1] ⊕ Sold[7])
    u128 t4 = aes_inv_round(s[5], t3);  // Sold[4] = AES_INV(S[5] ⊕ Sold[3])
    u128 t6 = xor_u128(s[7], t0);       // Sold[6] = S[7] ⊕ Sold[0]
    u128 t5 = aes_inv_round(s[6], t4);  // Sold[5] = AES_INV(S[6] ⊕ Sold[4])
    u128 t1 = xor_u128(s[2], t6);       // Sold[1] = S[2] ⊕ Sold[6]
    u128 t2 = aes_inv_round(s[3], t1);  // Sold[2] = AES_INV(S[3] ⊕ Sold[1])

    s[0] = t0;
    s[1] = t1;
    s[2] = t2;
    s[3] = t3;
    s[4] = t4;
    s[5] = t5;
    s[6] = t6;
    s[7] = t7;
}

void rocca_init(rocca_state s,
                       const uint8_t key[ROCCA_KEY_SIZE],
                       const uint8_t nonce[ROCCA_NONCE_SIZE]) {
    u128 z0 = load_u128(Z0);
    u128 z1 = load_u128(Z1);
    u128 k0 = load_u128(&key[0]);
    u128 k1 = load_u128(&key[ROCCA_KEY_SIZE / 2]);
    u128 N  = load_u128(nonce);

    // First, (N,K0,K1) is loaded into the state S in the
    // following way:
    s[0] = k1;              // S[0] = K1
    s[1] = N;               // S[1] = N
    s[2] = z0;              // S[2] = Z0
    s[3] = z1;              // S[3] = Z1
    s[4] = xor_u128(N, k1); // S[4] = N ⊕ K1
    s[5] = zero_u128();     // S[5] = 0
    s[6] = k0;              // S[6] = K0
    s[7] = zero_u128();     // S[7] = 0

    // Then, 20 iterations of the round function R(S,Z0,Z1) is
    // applied to the state S.
    for (int i = 0; i < ROCCA_ROUNDS; i++) {
        rocca_update(s, z0, z1);
    }
}

static void rocca_enc(rocca_state s,
                      uint8_t dst[ROCCA_BLOCK_SIZE],
                      const uint8_t src[ROCCA_BLOCK_SIZE]) {
    u128 m0 = load_u128(&src[0]);
    u128 m1 = load_u128(&src[ROCCA_BLOCK_SIZE / 2]);

    // Ci0 = AES(S[1], S[5]) ⊕ M0i
    u128 c0 = aes_round(s[1], s[5]);
    c0      = xor_u128(c0, m0);

    // Ci1 = AES(S[0] ⊕ S[4], S[2]) ⊕ M1i
    u128 c1 = xor_u128(s[0], s[4]);
    c1      = aes_round(c1, s[2]);
    c1      = xor_u128(c1, m1);

    store_u128(&dst[0], c0);
    store_u128(&dst[ROCCA_BLOCK_SIZE / 2], c1);

    // R(S, Mi0, Mi1)
    rocca_update(s, m0, m1);
}

static void rocca_dec(rocca_state s,
                      uint8_t dst[ROCCA_BLOCK_SIZE],
                      const uint8_t src[ROCCA_BLOCK_SIZE]) {
    u128 c0 = load_u128(&src[0]);
    u128 c1 = load_u128(&src[ROCCA_BLOCK_SIZE / 2]);

    u128 m0 = aes_round(s[1], s[5]);
    m0      = xor_u128(m0, c0);

    u128 m1 = xor_u128(s[0], s[4]);
    m1      = aes_round(m1, s[2]);
    m1      = xor_u128(m1, c1);

    store_u128(&dst[0], m0);
    store_u128(&dst[ROCCA_BLOCK_SIZE / 2], m1);

    rocca_update(s, m0, m1);
}

static void rocca_dec_partial(rocca_state s,
                              uint8_t* dst,
                              size_t dst_len,
                              const uint8_t src[ROCCA_BLOCK_SIZE]) {
    u128 c0 = load_u128(&src[0]);
    u128 c1 = load_u128(&src[ROCCA_BLOCK_SIZE / 2]);

    u128 m0 = aes_round(s[1], s[5]);
    m0      = xor_u128(m0, c0);

    u128 m1 = xor_u128(s[0], s[4]);
    m1      = aes_round(m1, s[2]);
    m1      = xor_u128(m1, c1);

    uint8_t pad[ROCCA_BLOCK_SIZE] = {0};
    store_u128(&pad[0], m0);
    store_u128(&pad[ROCCA_BLOCK_SIZE / 2], m1);
    memset(&pad[dst_len], 0, sizeof(pad) - dst_len);
    memcpy(dst, pad, dst_len);

    u128 p0 = load_u128(&pad[0]);
    u128 p1 = load_u128(&pad[ROCCA_BLOCK_SIZE / 2]);
    rocca_update(s, p0, p1);
}

static void put_le64(uint8_t* b, uint64_t v) {
    b[0] = (uint8_t)(v);
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
    b[4] = (uint8_t)(v >> 32);
    b[5] = (uint8_t)(v >> 40);
    b[6] = (uint8_t)(v >> 48);
    b[7] = (uint8_t)(v >> 56);
}

u128 rocca_mac(rocca_state s,
                      uint64_t additional_data_len,
                      uint64_t plaintext_len) {
    uint8_t buf[16] = {0};
    
    put_le64(buf, additional_data_len * 8);
    u128 ad = load_u128(buf);

    put_le64(buf, plaintext_len * 8);
    u128 pt = load_u128(buf);

    //  for i = 0 to 19 do
    //    S ← R(S, |AD|, |M|)
    for (int i = 0; i < ROCCA_ROUNDS; i++) {
        rocca_update(s, ad, pt);
    }

    //  T ← 0
    //  for i = 0 to 7 do
    //    T ← T ⊕ S[i]
    u128 tag = s[0];
    for (int i = 1; i < 8; i++) {
        tag = xor_u128(tag, s[i]);
    }
    return tag;
}

bool rocca_seal(uint8_t* dst,
                size_t dst_len,
                const uint8_t key[ROCCA_KEY_SIZE],
                size_t key_len,
                const uint8_t nonce[ROCCA_NONCE_SIZE],
                size_t nonce_len,
                const uint8_t* plaintext,
                size_t plaintext_len,
                const uint8_t* additional_data,
                size_t additional_data_len) {
    if (dst == NULL) {
        return false;
    }
    if ((SIZE_MAX - plaintext_len) < ROCCA_OVERHEAD) {
        memset(dst, 0, dst_len);
        return false;
    }
    if (key == NULL || key_len != ROCCA_KEY_SIZE) {
        memset(dst, 0, dst_len);
        return false;
    }
    if (nonce == NULL || nonce_len != ROCCA_NONCE_SIZE) {
        memset(dst, 0, dst_len);
        return false;
    }
    if (((plaintext == NULL) != (plaintext_len == 0)) ||
        ((additional_data == NULL) != (additional_data_len == 0))) {
        memset(dst, 0, dst_len);
        return false;
    }

    rocca_state s = {0};
    rocca_init(s, key, nonce);

    uint8_t tmp[ROCCA_BLOCK_SIZE] = {0};

    // Authenticate full blocks.
    size_t nblocks = additional_data_len / ROCCA_BLOCK_SIZE;
    for (size_t i = 0; i < nblocks; i++) {
        u128 a0 = load_u128(&additional_data[i * ROCCA_BLOCK_SIZE]);
        u128 a1 = load_u128(
            &additional_data[i * ROCCA_BLOCK_SIZE + ROCCA_BLOCK_SIZE / 2]);
        rocca_update(s, a0, a1);
    }

    // Authenticate a partial block.
    size_t remain = additional_data_len % ROCCA_BLOCK_SIZE;
    if (remain != 0) {
        memset(tmp, 0, sizeof(tmp));
        memcpy(tmp, additional_data, remain);
        u128 a0 = load_u128(&tmp[0]);
        u128 a1 = load_u128(&tmp[ROCCA_BLOCK_SIZE / 2]);
        rocca_update(s, a0, a1);
    }

    // Encrypt full blocks.
    nblocks = plaintext_len / ROCCA_BLOCK_SIZE;
    for (size_t i = 0; i < nblocks; i++) {
        rocca_enc(s, &dst[i * ROCCA_BLOCK_SIZE],
                  &plaintext[i * ROCCA_BLOCK_SIZE]);
    }

    // Encrypt a partial block.
    remain = plaintext_len % ROCCA_BLOCK_SIZE;
    if (remain != 0) {
        memset(tmp, 0, sizeof(tmp));
        memcpy(tmp, plaintext, remain);
        rocca_enc(s, tmp, tmp);
        memcpy(dst, tmp, remain);
    }

    u128 tag = rocca_mac(s, additional_data_len, plaintext_len);
    store_u128(&dst[(nblocks * ROCCA_BLOCK_SIZE) + remain], tag);
    memset(tmp, 0, sizeof(tmp));

    return true;
}

bool rocca_open(uint8_t* dst,
                size_t dst_len,
                const uint8_t key[ROCCA_KEY_SIZE],
                size_t key_len,
                const uint8_t nonce[ROCCA_NONCE_SIZE],
                size_t nonce_len,
                const uint8_t* ciphertext,
                size_t ciphertext_len,
                const uint8_t* additional_data,
                size_t additional_data_len) {
    if (dst == NULL) {
        return false;
    }
    if (ciphertext == NULL || ciphertext_len < ROCCA_OVERHEAD) {
        memset(dst, 0, dst_len);
        return false;
    }
    if (key == NULL || key_len != ROCCA_KEY_SIZE) {
        memset(dst, 0, dst_len);
        return false;
    }
    if (nonce == NULL || nonce_len != ROCCA_NONCE_SIZE) {
        memset(dst, 0, dst_len);
        return false;
    }
    if ((additional_data == NULL) != (additional_data_len == 0)) {
        memset(dst, 0, dst_len);
        return false;
    }

    ciphertext_len -= ROCCA_TAG_SIZE;
    u128 tag = load_u128(&ciphertext[ciphertext_len]);

    rocca_state s = {0};
    rocca_init(s, key, nonce);

    uint8_t tmp[ROCCA_BLOCK_SIZE] = {0};

    // Authenticate full blocks.
    size_t nblocks = additional_data_len / ROCCA_BLOCK_SIZE;
    for (size_t i = 0; i < nblocks; i++) {
        u128 a0 = load_u128(&additional_data[i * ROCCA_BLOCK_SIZE]);
        u128 a1 = load_u128(
            &additional_data[i * ROCCA_BLOCK_SIZE + ROCCA_BLOCK_SIZE / 2]);
        rocca_update(s, a0, a1);
    }

    // Authenticate a partial block.
    size_t remain = additional_data_len % ROCCA_BLOCK_SIZE;
    if (remain != 0) {
        memset(tmp, 0, sizeof(tmp));
        memcpy(tmp, additional_data, remain);
        u128 a0 = load_u128(&tmp[0]);
        u128 a1 = load_u128(&tmp[ROCCA_BLOCK_SIZE / 2]);
        rocca_update(s, a0, a1);
    }

    // Decrypt full blocks.
    nblocks = ciphertext_len / ROCCA_BLOCK_SIZE;
    for (size_t i = 0; i < nblocks; i++) {
        rocca_dec(s, &dst[i * ROCCA_BLOCK_SIZE],
                  &ciphertext[i * ROCCA_BLOCK_SIZE]);
    }

    // Decrypt a partial block.
    remain = ciphertext_len % ROCCA_BLOCK_SIZE;
    if (remain != 0) {
        memset(tmp, 0, sizeof(tmp));
        memcpy(tmp, ciphertext, remain);
        rocca_dec_partial(s, &dst[nblocks * ROCCA_BLOCK_SIZE], remain, tmp);
    }

    memset(tmp, 0, sizeof(tmp));

    u128 expectedTag = rocca_mac(s, additional_data_len, ciphertext_len);
    if (!constant_time_compare_u128(tag, expectedTag)) {
        memset(dst, 0, dst_len);
        return false;
    }
    return true;
}
