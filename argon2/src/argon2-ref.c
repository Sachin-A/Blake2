#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "argon2.h"
#include "argon2-ref.h"
#include "../blake2b/include/blake2b.h"

#define MULT64(x , y) ( 2 * ( x & UINT64_C(0xFFFFFFFF) ) * ( y & UINT64_C(0xFFFFFFFF) ) );

/**
 * The blake2 mixing function like macro mixes two 8-byte words from the message
 * into the hash state
 *
 * @params  a, b, c, d  indices to 8-byte word entries from the work vector V
 */

#define G(a, b, c, d)                                                          \
    do {                                                                       \
        a = a + b + MULT64(a,b);                                               \
        d = rotr64(d ^ a, 32);                                                 \
        c = c + d + MULT64(c,d);                                               \
        b = rotr64(b ^ c, 24);                                                 \
        a = a + b + MULT64(a,b);                                               \
        d = rotr64(d ^ a, 16);                                                 \
        c = c + d + MULT64(c,d);                                               \
        b = rotr64(b ^ c, 63);                                                 \
    } while (0)

#define BLAKE2_ROUND(v0, v1, v2, v3, v4, v5, v6, v7, v8,					   \
					 v9, v10, v11, v12, v13, v14, v15)  					   \
					 							                               \
    do {                                                                       \
        G(v0, v4, v8,  v12);                                                   \
        G(v1, v5, v9,  v13);                                                   \
        G(v2, v6, v10, v14);                                                   \
        G(v3, v7, v11, v15);                                                   \
        G(v0, v5, v10, v15);                                                   \
        G(v1, v6, v11, v12);                                                   \
        G(v2, v7, v8,  v13);                                                   \
        G(v3, v4, v9,  v14);                                                   \
    } while (0)

/**
 * Function fills a new memory block and optionally XORs the old block over the new one.
 * @next_block must be initialized.
 * @param prev_block Pointer to the previous block
 * @param ref_block Pointer to the reference block
 * @param next_block Pointer to the block to be constructed
 * @param with_xor Whether to XOR into the new block (1) or just overwrite (0)
 * @pre all block pointers must be valid
 */

void fill_block(const block *prev_block, const block *ref_block, block *next_block, int with_xor) 
{
    block blockR, block_tmp;
    size_t i;

    copy_block(&blockR, ref_block);
    xor_block(&blockR, prev_block);
    copy_block(&block_tmp, &blockR);
    
    /**
     *Now blockR = ref_block + prev_block and block_tmp = ref_block + prev_block 
     */
    
    if (with_xor) {
        
        /** 
         *Saving the next block contents for XOR over: 
         */
        
        xor_block(&block_tmp, next_block);
        
        /** 
         *Now blockR = ref_block + prev_block and
         *block_tmp = ref_block + prev_block + next_block 
         */
    }

    /**
     *Apply Blake2 on columns of 64-bit words: (0,1,...,15) , then
     *(16,17,..31)... finally (112,113,...127) 
     */
    
    for (i = 0; i < 8; ++i) {
        
        BLAKE2_ROUND(blockR.v[16 * i], blockR.v[16 * i + 1] , blockR.v[16 * i + 2] ,
            	blockR.v[16 * i + 3] , blockR.v[16 * i + 4] , blockR.v[16 * i + 5] ,
           		blockR.v[16 * i + 6] , blockR.v[16 * i + 7] , blockR.v[16 * i + 8] ,
            	blockR.v[16 * i + 9] , blockR.v[16 * i + 10], blockR.v[16 * i + 11],
           		blockR.v[16 * i + 12], blockR.v[16 * i + 13], blockR.v[16 * i + 14],
           		blockR.v[16 * i + 15]);
    }

    /** 
     *Apply Blake2 on rows of 64-bit words: (0,1,16,17,...112,113), then
     *(2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127) 
     */
    
    for (i = 0; i < 8; i++) {
        
        BLAKE2_ROUND(blockR.v[2 * i], blockR.v[2 * i + 1] , blockR.v[2 * i + 16] ,
            	blockR.v[2 * i + 17], blockR.v[2 * i + 32], blockR.v[2 * i + 33] ,
            	blockR.v[2 * i + 48], blockR.v[2 * i + 49], blockR.v[2 * i + 64] ,
            	blockR.v[2 * i + 65], blockR.v[2 * i + 80], blockR.v[2 * i + 81] ,
            	blockR.v[2 * i + 96], blockR.v[2 * i + 97], blockR.v[2 * i + 112],
            	blockR.v[2 * i + 113]);
    }

    copy_block(next_block, &block_tmp);
    xor_block(next_block, &blockR);
}

static void next_addresses(block *address_block, block *input_block, const block *zero_block) 
{
    input_block->v[6]++;
    fill_block(zero_block, input_block, address_block, 0);
    fill_block(zero_block, address_block, address_block, 0);
}

/**
 * Function that fills the segment using previous segments also from other threads
 * @param context current context
 * @param instance Pointer to the current instance
 * @param position Current position
 * @pre all block pointers must be valid
 */

void fill_segment(const argon2_instance_t *instance, argon2_position_t position)
{
    
    block *ref_block = NULL, *curr_block = NULL;
    block address_block, input_block, zero_block;
    
    uint64_t pseudo_rand, ref_index, ref_lane;
    uint32_t prev_offset, curr_offset;
    uint32_t starting_index;
    size_t i;
    
    int data_independent_addressing;

    if (NULL == instance) {
        return;
    }

    data_independent_addressing = (instance->type == Argon2_i) || 
    							  (instance->type == Argon2_id && 
    							  (position.pass == 0) &&
                                  (position.slice < ARGON2_SYNC_POINTS / 2));

    if (data_independent_addressing) {
        
        init_block_value(&zero_block, 0);
        init_block_value(&input_block, 0);

        input_block.v[0] = position.pass;
        input_block.v[1] = position.lane;
        input_block.v[2] = position.slice;
        input_block.v[3] = instance->memory_blocks;
        input_block.v[4] = instance->passes;
        input_block.v[5] = instance->type;
    }

    starting_index = 0;

    if ((0 == position.pass) && (0 == position.slice)) {
        /**
         * we have already generated the first two blocks 
         */
        starting_index = 2; 
        
        if (data_independent_addressing) {
            next_addresses(&address_block, &input_block, &zero_block);
        }
    }

    /** 
     * Offset of the current block 
     */
    
    curr_offset = position.lane  * instance->lane_length    +
                  position.slice * instance->segment_length + starting_index;

    if (0 == curr_offset % instance->lane_length) {
        prev_offset = curr_offset + instance->lane_length - 1;
    } 
    else {
        prev_offset = curr_offset - 1;
    }

    for (i = starting_index; i < instance->segment_length; 
    		++i, ++curr_offset, ++prev_offset) {
        /**
         * Rotating prev_offset if needed 
         */
        
        if (curr_offset % instance->lane_length == 1) {
            prev_offset = curr_offset - 1;
        }

        /**
         * Computing the index of the reference block 
         */
        
        /**
         * a. Taking pseudo-random value from the previous block 
         */
        
        if (data_independent_addressing) {
            if ( 0 == i % ARGON2_ADDRESSES_IN_BLOCK) {
                next_addresses(&address_block, &input_block, &zero_block);
            }
            pseudo_rand = address_block.v[i % ARGON2_ADDRESSES_IN_BLOCK];
        } 
        else {
            pseudo_rand = instance->memory[prev_offset].v[0];
        }

        /**
         * b. Computing the lane of the reference block 
         */
        
        ref_lane = ((pseudo_rand >> 32)) % instance->lanes;

        if ((position.pass == 0) && (position.slice == 0)) {
            
            /** 
             *Can not reference other lanes yet 
             */
            
            ref_lane = position.lane;
        }

        /** 
         *c. Computing the number of possible reference block within the lane.
         */
        
        position.index = i;
        ref_index = index_alpha(instance, &position, pseudo_rand & 0xFFFFFFFF,
                                ref_lane == position.lane);

        ref_block = instance->memory + instance->lane_length * ref_lane + ref_index;
        curr_block = instance->memory + curr_offset;
        
        if (ARGON2_VERSION_10 == instance->version) {
            fill_block(instance->memory + prev_offset, ref_block, curr_block, 0);
        } 
        else {
            
            if(0 == position.pass) {
                fill_block(instance->memory + prev_offset, ref_block,
                           curr_block, 0);
            } 
            else {
                fill_block(instance->memory + prev_offset, ref_block,
                           curr_block, 1);
            }
        }
    }
}