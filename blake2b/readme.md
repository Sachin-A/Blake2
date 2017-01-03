BLAKE2
======

- BLAKE2 is an improved version of the SHA-3 finalist BLAKE, and was designed by a team of experts in cryptanalysis, implementation, and cryptographic engineering; namely Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn and Christian Winnerlein.

- BLAKE2s (the one checksum currently uses) computes a message digest that is 256 bits long, and represented as a 64-character hexadecimal number, e.g.   ```4264cb256d94533b6e152da59256638bc6adfda3efc5550d7607d4e6e45592fc.```

## Types

- BLAKE2b (or just BLAKE2) is optimized for 64-bit platforms and produces digests of any size between 1 and 64 bytes.
- BLAKE2s is optimized for 8-bit to 32-bit platforms and produces digests of any size between 1 and 32 bytes.

## Key Features

- BLAKE2 does not require a special "HMAC" (Hashed Message Authentication Code) construction
   for keyed message authentication as it has a built-in keying mechanism.

## Use cases

- can be used by digital signature algorithms and message authentication and integrity protection mechanisms in applications such as Public Key Infrastructure (PKI), secure communication protocols, cloud storage, intrusion detection, forensic suites, and version control systems.
- BLAKE2s-128 is especially suited as a fast and more secure drop-in replacement to MD5 and HMAC-MD5 in legacy applications

---

## Algorithm Description

### Structure and Terminology

```
+--------------+------------------+------------------+
|              | BLAKE2b          | BLAKE2s          |
+--------------+------------------+------------------+
| Bits in word | w  = 64          | w  = 32          |
| Rounds in F  | r  = 12          | r  = 10          |
| Block bytes  | bb = 128         | bb = 64          |
| Hash bytes   | 1 <= nn <= 64    | 1 <= nn <= 32    |
| Key bytes    | 0 <= kk <= 64    | 0 <= kk <= 32    |
| Input bytes  | 0 <= ll < 2**128 | 0 <= ll < 2**64  |
+--------------+------------------+------------------+
| G Rotation   | (R1, R2, R3, R4) | (R1, R2, R3, R4) |
|  constants   | (32, 24, 16, 63) | (16, 12,  8,  7) |
+--------------+------------------+------------------+
```
```F```, the compression function and ```G```, the mixing function are described later

### Other constants and variables

```
IV[0..7]    :: Initialization Vector (constant).

SIGMA[0..9] :: Message word permutations (constant).

p[0..7]     :: Parameter block (defines hash and key sizes).

m[0..15]    :: Sixteen words of a single message block.

h[0..7]     :: Internal state of the hash.

d[0..dd-1]  :: Padded input blocks. Each has "bb" bytes.

t           :: Message byte offset at the end of the current block.

f           :: Flag indicating the last block.
```

### Blake2 Processing

#### Mixing Function G

Description :: The G primitive function mixes two input words, "x" and "y", into four words indexed by "a", "b", "c", and "d" in the working vector v[0..15].  The full modified vector is returned.

```
FUNCTION G( v[0..15], a, b, c, d, x, y )

    v[a] := (v[a] + v[b] + x) mod 2**w
    v[d] := (v[d] ^ v[a]) >>> R1
    v[c] := (v[c] + v[d])     mod 2**w
    v[b] := (v[b] ^ v[c]) >>> R2
    v[a] := (v[a] + v[b] + y) mod 2**w
    v[d] := (v[d] ^ v[a]) >>> R3
    v[c] := (v[c] + v[d])     mod 2**w
    v[b] := (v[b] ^ v[c]) >>> R4

    RETURN v[0..15]

END FUNCTION.
```
#### Compression Function F

1. Inputs
    - ```h```: state vector
    - ```m```: message block vector (last block is padded with zeros to full block size, if required)
    - ```t```: 2w-bit offset counter
    - ```f```: final block indicator flag

2. Local variables
    - ```v[0..15]```: Local vector used in processing
    - ```r```: The number of rounds (12 for BLAKE2b and 10 for BLAKE2s)

3. Output
    - new state vector

```
FUNCTION F( h[0..7], m[0..15], t, f )

    // Initialize local work vector v[0..15]
    v[0..7] := h[0..7]              // First half from state.
    v[8..15] := IV[0..7]            // Second half from IV.

    v[12] := v[12] ^ (t mod 2**w)   // Low word of the offset.
    v[13] := v[13] ^ (t >> w)       // High word.

    IF f = TRUE THEN                // last block flag?
       v[14] := v[14] ^ 0xFF..FF   // Invert all bits.
    END IF.

    // Cryptographic mixing
    FOR i = 0 TO r - 1 DO           // Ten or twelve rounds.

        // Message word selection permutation for this round.
        s[0..15] := SIGMA[i mod 10][0..15]

        v := G( v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]] )
        v := G( v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]] )
        v := G( v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]] )
        v := G( v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]] )

        v := G( v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]] )
        v := G( v, 1, 6, 11, 12, m[s[10]], m[s[11]] )
        v := G( v, 2, 7,  8, 13, m[s[12]], m[s[13]] )
        v := G( v, 3, 4,  9, 14, m[s[14]], m[s[15]] )

    END FOR

    FOR i = 0 TO 7 DO               // XOR the two halves.
        h[i] := h[i] ^ v[i] ^ v[i + 8]
    END FOR.

    RETURN h[0..7]                  // New state.

END FUNCTION.
```

#### Blake2

- Key and data input are split and padded into "dd" message blocks
  d[0..dd-1], each consisting of 16 words (or "bb" bytes).

- If a secret key is used (kk > 0), it is padded with zero bytes and
   set as d[0].  Otherwise, d[0] is the first data block.  The final
   data block d[dd-1] is also padded with zero to "bb" bytes (16 words).

- The number of blocks is therefore dd = ceil(kk / bb) + ceil(ll / bb).
   However, in the special case of an unkeyed empty message (kk = 0 and
   ll = 0), we still set dd = 1 and d[0] consists of all zeros.

- The following procedure processes the padded data blocks into an
   "nn"-byte final hash value.

```
FUNCTION BLAKE2( d[0..dd-1], ll, kk, nn )

    h[0..7] := IV[0..7]          // Initialization Vector.

    // Parameter block p[0]
    h[0] := h[0] ^ 0x01010000 ^ (kk << 8) ^ nn

    // Process padded key and data blocks
    IF dd > 1 THEN
        FOR i = 0 TO dd - 2 DO
            h := F( h, d[i], (i + 1) * bb, FALSE )
        END FOR.
    END IF.

    // Final block.
    IF kk = 0 THEN
        h := F( h, d[dd - 1], ll, TRUE )
    ELSE
        h := F( h, d[dd - 1], ll + bb, TRUE )
    END IF.

    RETURN first "nn" bytes from little-endian word array h[].

END FUNCTION.
```

---

## BLAKE2 Tree mode/Unlimited fanout

In addition to the 'normal' sequential mode that most hashing algorithms use, BLAKE2 has a very flexible tree-hashing. BLAKE2 supports arbitrary-depth trees as well as a special mode called unlimited fanout

```
                 /=====\
                 | 2:0 |
                 \=====/
               /         \
              /           \
         /=====\         /=====\
         | 1:0 |         | 1:1 |
         \=====/         \=====/
       /    |    \              \
      /     |     \              \
/-----\  /-----\  /-----\       /-----\  
| 0:0 |  | 0:1 |  | 0:2 |       | 0:3 |  
\-----/  \-----/  \-----/       \-----/  

```

In this diagram the boxes represent leaves whereby the label `i:j` represents a node's depth `i` and offset `j`. Double-lined nodes (including leaves) are the last nodes of a layer. The leaves process chunks of data of `leaf length` bytes independently of each other, and subsequently the root node hashes the concatenation of the hashes of the leaves.

For BLAKE2's unlimited fanout mode the depth is always fixed at 2 and there can be as many leaves as are required given the size of the input. Note that the `node offset` and `node depth` parameters ensure that each invocation of BLAKE2 uses a different hash function (and hence will generate a different output for the same input).


## Design of Code

THe following modules would be exposed as part of the blake2 API

### 1. BLAKE2b

```C
    // state context
    typedef struct {
       uint8_t b[128];                     // input buffer
       uint64_t h[8];                      // chained state
       uint64_t t[2];                      // total number of bytes
       size_t c;                           // pointer for b[]
       size_t outlen;                      // digest size
    } blake2b_ctx;


    // Initialize the hashing context "ctx" with optional key "key".
    //      1 <= outlen <= 64 gives the digest size in bytes.
    //      Secret key (also <= 64 bytes) is optional (keylen = 0).
    int blake2b_init(blake2b_ctx *ctx, size_t outlen,
       const void *key, size_t keylen);    // secret key

    // Add "inlen" bytes from "in" into the hash.
    void blake2b_update(blake2b_ctx *ctx,   // context
       const void *in, size_t inlen);      // data to be hashed

    // Generate the message digest (size given in init).
    //      Result placed in "out".
    void blake2b_final(blake2b_ctx *ctx, void *out);

    // All-in-one convenience function.
    int blake2b(void *out, size_t outlen,   // return buffer for digest
       const void *key, size_t keylen,     // optional secret key
       const void *in, size_t inlen);      // data to be hashed

```

### 2. BLAKE2s

```C
    // state context
    typedef struct {
       uint8_t b[64];                      // input buffer
       uint32_t h[8];                      // chained state
       uint32_t t[2];                      // total number of bytes
       size_t c;                           // pointer for b[]
       size_t outlen;                      // digest size
    } blake2s_ctx;

    // Initialize the hashing context "ctx" with optional key "key".
    //      1 <= outlen <= 32 gives the digest size in bytes.
    //      Secret key (also <= 32 bytes) is optional (keylen = 0).
    int blake2s_init(blake2s_ctx *ctx, size_t outlen,
       const void *key, size_t keylen);    // secret key

    // Add "inlen" bytes from "in" into the hash.
    void blake2s_update(blake2s_ctx *ctx,   // context
       const void *in, size_t inlen);      // data to be hashed

    // Generate the message digest (size given in init).
    //      Result placed in "out".
    void blake2s_final(blake2s_ctx *ctx, void *out);

    // All-in-one convenience function.
    int blake2s(void *out, size_t outlen,   // return buffer for digest
       const void *key, size_t keylen,     // optional secret key
       const void *in, size_t inlen);      // data to be hashed

```

---

## BLAKE2x 

BLAKE2X is an XOF(Extendible Output Function -> hash functions that produce hash values of arbitrary length) which can be derived from any BLAKE2 instance

### Byproducts 

- Deterministic  random  bit  generator  (DRBG):  Given  a  high-entropy  seed,  BLAKE2X produces a stream of up to 256 GiB.
- Key derivation function (KDF): Given input key material (and an optional salt, as allowed by the BLAKE2 parameter block),  BLAKE2X computes a key of up to 2**32-2 bytes (about 4 GiB). 

### Construction from Blake2

BLAKE2X requires a slightly modified version of the parameter block, where the length of the "Node offset" field is reduced from 8 to 4 bytes for 64-bit BLAKE2, and from 6 to 4 bytes for 32-bit BLAKE2. This change does not break compatibility with already used BLAKE2 versions. 

Given a 64-bit BLAKE2 instance such as BLAKE2b, BLAKE2X works as follows to compute an ```l```-byte hash of some message ```M```:

1. Set the "XOF digest length" parameter to a little-endian encoding of ```l```. If the output length is unknown in advance, ```l``` should be set to the maximal value 2**32 - 1 
2. Compute the hash of ```M``` using the underlying BLAKE2 instance as usual. Call the result ```H0```
3. Create the hash function instance B2 from the BLAKE2 instance used, where
    - ```Maximal depth``` is set to 0
    - ```XOF digest length``` is set to
    - ```Fanout``` is set to 0(unlimited)
    - ```Leaf maximal byte length``` is set to 32 for BLAKE2Xs, and 64 for BLAKE2Xb
    - ```Node depth``` is set to 0 (leaves)
    - ```Inner hash byte length``` is set to 32 for BLAKE2Xs and 64 for BLAKE2Xb
    - Other fields are left to the same values as in the underlying BLAKE2 instance
    - B2 (i, j, X) denotes the hash of X using i as node offset and j as digest length
4. The final hash is computed as follows  
    ```
    B2(0, 64, H0) || B2(1, 64, H0) || B2(2, 64, H0) 
    || ... || B2(floor(l/64), l mod 64, H0) 
    ```

## Further Reading

- [BLAKE2]   
  Aumasson, J-P., Neves, S., Wilcox-O'Hearn, Z., and C.  
  Winnerlein, "BLAKE2: simpler, smaller, fast as MD5",  
  January 2013, <https://blake2.net/blake2.pdf>.

- [RFC for Blake2]
  https://tools.ietf.org/html/rfc7693

- [BLAKE2X]   
  https://blake2.net/blake2x.pdf

