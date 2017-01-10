#ifndef ARGON2_REF_H
#define ARGON2_REF_H

#include "argon2-core.h"

void fill_block(const block *prev_block, const block *ref_block,
                block *next_block, int with_xor);
static void next_addresses(block *address_block, block *input_block,
				const block *zero_block);
void fill_segment(const argon2_instance_t *instance, 
				argon2_position_t position);

#endif /* ARGON2_REF_H */