#include "utils.h"

/**
 * Helper function to perform rotation of a 32 bit int
 *
 */
uint32_t rotr32(const uint32_t w, const unsigned c)
{
  return (w >> c) | (w << (32 - c));
}


/**
 * Helper function to load 32 bytes at a time into src
 */
uint32_t load32( const void *src )
{
#if defined(NATIVE_LITTLE_ENDIAN)
  uint32_t w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  const uint8_t *p = ( const uint8_t * )src;
  return (( uint32_t )( p[0] ) <<  0) |
         (( uint32_t )( p[1] ) <<  8) |
         (( uint32_t )( p[2] ) << 16) |
         (( uint32_t )( p[3] ) << 24) ;
#endif
}

/**
 * Stores 16 bit w into a dst
 */

void store16( void *dst, uint16_t w )
{
#if defined(NATIVE_LITTLE_ENDIAN)
  memcpy(dst, &w, sizeof w);
#else
  uint8_t *p = ( uint8_t * )dst;
  *p++ = ( uint8_t )w; w >>= 8;
  *p++ = ( uint8_t )w;
#endif
}

/**
 * Stores w into a dst
 */
void store32(void* dst, uint32_t w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
  memcpy(dst, &w, sizeof w);
#else
  uint8_t* p = (uint8_t*)dst;
  p[0] = (uint8_t)(w >> 0);
  p[1] = (uint8_t)(w >> 8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
#endif
}


/**
 * Blake2s increment counter
 */
void blake2s_increment_counter(blake2s_state* S, const uint32_t inc)
{
  S->t[0] += inc ;
  S->t[1] += (S->t[0] < inc);
}
