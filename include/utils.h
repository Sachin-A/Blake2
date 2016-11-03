#ifndef UTILS_H
#define UTILS_H

#include "blake2b.h"

uint64_t rotr64(const uint64_t w, const unsigned c);
uint64_t load64(const void* src);
void store64(void* dst, uint64_t w);

#endif
