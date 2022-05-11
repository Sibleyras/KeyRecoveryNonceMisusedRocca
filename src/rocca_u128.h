#ifndef U128_UTIL
#define U128_UTIL

#include "aes.h"

#include <string.h>

typedef __uint128_t u128;

inline u128 aes_round(u128 in, u128 rk) {
    u128 res = in;
    aes_oneround((uint8_t *) &res);
    return res ^ rk;
}

inline u128 aes_inv_round(u128 in, u128 rk) {
    u128 res = in ^ rk;
    aes_inv_oneround((uint8_t *) &res);
    return res;
}

inline u128 load_u128(const void* src) {
    u128 res;
    memcpy(&res, src, sizeof(u128));
    return res;
}

inline void store_u128(uint8_t* dst, u128 x) {
    memcpy(dst, &x, sizeof(u128));
}

inline u128 xor_u128(u128 a, u128 b) {
    return a ^ b;
}

inline u128 and_u128(u128 a, u128 b) {
    return a & b;
}

inline u128 or_u128(u128 a, u128 b) {
    return a | b;
}

inline u128 zero_u128(void) {
    return (u128) 0;
}

inline bool constant_time_compare_u128(u128 a, u128 b) {
    return a == b;
}

#endif // U128_UTIL
