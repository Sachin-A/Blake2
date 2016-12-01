#ifndef UTILS_H
#define UTILS_H

#include "blake2s.h"

uint32_t rotr32(const uint32_t w, const unsigned c);
uint32_t load32(const void* src);
void store32(void* dst, unint32_t w);
void blake2s_increment_counter(blake2s_state* S, coinst uint32_t inc):

#endif