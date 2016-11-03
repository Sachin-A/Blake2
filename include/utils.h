#ifndef UTILS_H
#define UTILS_H

#include "blake2b.h"

uint64_t rotr64(const uint64_t w, const unsigned c);
uint64_t load64(const void* src);
void store64(void* dst, uint64_t w);
void blake2b_increment_counter(blake2b_state* S, const uint64_t inc);
int blake2b_is_lastblock(const blake2b_state* S);
void blake2b_set_lastblock(blake2b_state *S);

#endif
