#include <stdint.h>
#include "type.h"
typedef uint64_ow REF10_uint64;

static REF10_uint64 REF10_load_bigendian(const unsigned char *x)
{
  return
      (REF10_uint64) (x[7]) \
  | (((REF10_uint64) (x[6])) << 8) \
  | (((REF10_uint64) (x[5])) << 16) \
  | (((REF10_uint64) (x[4])) << 24) \
  | (((REF10_uint64) (x[3])) << 32) \
  | (((REF10_uint64) (x[2])) << 40) \
  | (((REF10_uint64) (x[1])) << 48) \
  | (((REF10_uint64) (x[0])) << 56)
  ;
}

static void REF10_store_bigendian(unsigned char *x,REF10_uint64 u)
{
  x[7] = u; u >>= 8;
  x[6] = u; u >>= 8;
  x[5] = u; u >>= 8;
  x[4] = u; u >>= 8;
  x[3] = u; u >>= 8;
  x[2] = u; u >>= 8;
  x[1] = u; u >>= 8;
  x[0] = u;
}

#define REF10_SHR(x,c) ((x) >> (c))
#define REF10_ROTR(x,c) (((x) >> (c)) | ((x) << (64 - (c))))

#define REF10_Ch(x,y,z) ((x & y) ^ (~x & z))
#define REF10_Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define REF10_Sigma0(x) (REF10_ROTR(x,28) ^ REF10_ROTR(x,34) ^ REF10_ROTR(x,39))
#define REF10_Sigma1(x) (REF10_ROTR(x,14) ^ REF10_ROTR(x,18) ^ REF10_ROTR(x,41))
#define REF10_sigma0(x) (REF10_ROTR(x, 1) ^ REF10_ROTR(x, 8) ^ REF10_SHR(x,7))
#define REF10_sigma1(x) (REF10_ROTR(x,19) ^ REF10_ROTR(x,61) ^ REF10_SHR(x,6))

#define REF10_M(w0,w14,w9,w1) w0 = REF10_sigma1(w14) + w9 + REF10_sigma0(w1) + w0;

#define REF10_EXPAND \
  REF10_M(w0 ,w14,w9 ,w1 ) \
  REF10_M(w1 ,w15,w10,w2 ) \
  REF10_M(w2 ,w0 ,w11,w3 ) \
  REF10_M(w3 ,w1 ,w12,w4 ) \
  REF10_M(w4 ,w2 ,w13,w5 ) \
  REF10_M(w5 ,w3 ,w14,w6 ) \
  REF10_M(w6 ,w4 ,w15,w7 ) \
  REF10_M(w7 ,w5 ,w0 ,w8 ) \
  REF10_M(w8 ,w6 ,w1 ,w9 ) \
  REF10_M(w9 ,w7 ,w2 ,w10) \
  REF10_M(w10,w8 ,w3 ,w11) \
  REF10_M(w11,w9 ,w4 ,w12) \
  REF10_M(w12,w10,w5 ,w13) \
  REF10_M(w13,w11,w6 ,w14) \
  REF10_M(w14,w12,w7 ,w15) \
  REF10_M(w15,w13,w8 ,w0 )

#define REF10_BLOCKS_F(w,k) \
  T1 = h + REF10_Sigma1(e) + REF10_Ch(e,f,g) + k + w; \
  T2 = REF10_Sigma0(a) + REF10_Maj(a,b,c); \
  h = g; \
  g = f; \
  f = e; \
  e = d + T1; \
  d = c; \
  c = b; \
  b = a; \
  a = T1 + T2;

int REF10_crypto_hashblocks_sha512(unsigned char *statebytes,const unsigned char *in,unsigned long long inlen)
{
  REF10_uint64 state[8];
  REF10_uint64 a;
  REF10_uint64 b;
  REF10_uint64 c;
  REF10_uint64 d;
  REF10_uint64 e;
  REF10_uint64 f;
  REF10_uint64 g;
  REF10_uint64 h;
  REF10_uint64 T1;
  REF10_uint64 T2;

  a = REF10_load_bigendian(statebytes +  0); state[0] = a;
  b = REF10_load_bigendian(statebytes +  8); state[1] = b;
  c = REF10_load_bigendian(statebytes + 16); state[2] = c;
  d = REF10_load_bigendian(statebytes + 24); state[3] = d;
  e = REF10_load_bigendian(statebytes + 32); state[4] = e;
  f = REF10_load_bigendian(statebytes + 40); state[5] = f;
  g = REF10_load_bigendian(statebytes + 48); state[6] = g;
  h = REF10_load_bigendian(statebytes + 56); state[7] = h;

  while (inlen >= 128) {
    REF10_uint64 w0  = REF10_load_bigendian(in +   0);
    REF10_uint64 w1  = REF10_load_bigendian(in +   8);
    REF10_uint64 w2  = REF10_load_bigendian(in +  16);
    REF10_uint64 w3  = REF10_load_bigendian(in +  24);
    REF10_uint64 w4  = REF10_load_bigendian(in +  32);
    REF10_uint64 w5  = REF10_load_bigendian(in +  40);
    REF10_uint64 w6  = REF10_load_bigendian(in +  48);
    REF10_uint64 w7  = REF10_load_bigendian(in +  56);
    REF10_uint64 w8  = REF10_load_bigendian(in +  64);
    REF10_uint64 w9  = REF10_load_bigendian(in +  72);
    REF10_uint64 w10 = REF10_load_bigendian(in +  80);
    REF10_uint64 w11 = REF10_load_bigendian(in +  88);
    REF10_uint64 w12 = REF10_load_bigendian(in +  96);
    REF10_uint64 w13 = REF10_load_bigendian(in + 104);
    REF10_uint64 w14 = REF10_load_bigendian(in + 112);
    REF10_uint64 w15 = REF10_load_bigendian(in + 120);

    REF10_BLOCKS_F(w0 ,0x428a2f98d728ae22ULL)
    REF10_BLOCKS_F(w1 ,0x7137449123ef65cdULL)
    REF10_BLOCKS_F(w2 ,0xb5c0fbcfec4d3b2fULL)
    REF10_BLOCKS_F(w3 ,0xe9b5dba58189dbbcULL)
    REF10_BLOCKS_F(w4 ,0x3956c25bf348b538ULL)
    REF10_BLOCKS_F(w5 ,0x59f111f1b605d019ULL)
    REF10_BLOCKS_F(w6 ,0x923f82a4af194f9bULL)
    REF10_BLOCKS_F(w7 ,0xab1c5ed5da6d8118ULL)
    REF10_BLOCKS_F(w8 ,0xd807aa98a3030242ULL)
    REF10_BLOCKS_F(w9 ,0x12835b0145706fbeULL)
    REF10_BLOCKS_F(w10,0x243185be4ee4b28cULL)
    REF10_BLOCKS_F(w11,0x550c7dc3d5ffb4e2ULL)
    REF10_BLOCKS_F(w12,0x72be5d74f27b896fULL)
    REF10_BLOCKS_F(w13,0x80deb1fe3b1696b1ULL)
    REF10_BLOCKS_F(w14,0x9bdc06a725c71235ULL)
    REF10_BLOCKS_F(w15,0xc19bf174cf692694ULL)

    REF10_EXPAND

    REF10_BLOCKS_F(w0 ,0xe49b69c19ef14ad2ULL)
    REF10_BLOCKS_F(w1 ,0xefbe4786384f25e3ULL)
    REF10_BLOCKS_F(w2 ,0x0fc19dc68b8cd5b5ULL)
    REF10_BLOCKS_F(w3 ,0x240ca1cc77ac9c65ULL)
    REF10_BLOCKS_F(w4 ,0x2de92c6f592b0275ULL)
    REF10_BLOCKS_F(w5 ,0x4a7484aa6ea6e483ULL)
    REF10_BLOCKS_F(w6 ,0x5cb0a9dcbd41fbd4ULL)
    REF10_BLOCKS_F(w7 ,0x76f988da831153b5ULL)
    REF10_BLOCKS_F(w8 ,0x983e5152ee66dfabULL)
    REF10_BLOCKS_F(w9 ,0xa831c66d2db43210ULL)
    REF10_BLOCKS_F(w10,0xb00327c898fb213fULL)
    REF10_BLOCKS_F(w11,0xbf597fc7beef0ee4ULL)
    REF10_BLOCKS_F(w12,0xc6e00bf33da88fc2ULL)
    REF10_BLOCKS_F(w13,0xd5a79147930aa725ULL)
    REF10_BLOCKS_F(w14,0x06ca6351e003826fULL)
    REF10_BLOCKS_F(w15,0x142929670a0e6e70ULL)

    REF10_EXPAND

    REF10_BLOCKS_F(w0 ,0x27b70a8546d22ffcULL)
    REF10_BLOCKS_F(w1 ,0x2e1b21385c26c926ULL)
    REF10_BLOCKS_F(w2 ,0x4d2c6dfc5ac42aedULL)
    REF10_BLOCKS_F(w3 ,0x53380d139d95b3dfULL)
    REF10_BLOCKS_F(w4 ,0x650a73548baf63deULL)
    REF10_BLOCKS_F(w5 ,0x766a0abb3c77b2a8ULL)
    REF10_BLOCKS_F(w6 ,0x81c2c92e47edaee6ULL)
    REF10_BLOCKS_F(w7 ,0x92722c851482353bULL)
    REF10_BLOCKS_F(w8 ,0xa2bfe8a14cf10364ULL)
    REF10_BLOCKS_F(w9 ,0xa81a664bbc423001ULL)
    REF10_BLOCKS_F(w10,0xc24b8b70d0f89791ULL)
    REF10_BLOCKS_F(w11,0xc76c51a30654be30ULL)
    REF10_BLOCKS_F(w12,0xd192e819d6ef5218ULL)
    REF10_BLOCKS_F(w13,0xd69906245565a910ULL)
    REF10_BLOCKS_F(w14,0xf40e35855771202aULL)
    REF10_BLOCKS_F(w15,0x106aa07032bbd1b8ULL)

    REF10_EXPAND

    REF10_BLOCKS_F(w0 ,0x19a4c116b8d2d0c8ULL)
    REF10_BLOCKS_F(w1 ,0x1e376c085141ab53ULL)
    REF10_BLOCKS_F(w2 ,0x2748774cdf8eeb99ULL)
    REF10_BLOCKS_F(w3 ,0x34b0bcb5e19b48a8ULL)
    REF10_BLOCKS_F(w4 ,0x391c0cb3c5c95a63ULL)
    REF10_BLOCKS_F(w5 ,0x4ed8aa4ae3418acbULL)
    REF10_BLOCKS_F(w6 ,0x5b9cca4f7763e373ULL)
    REF10_BLOCKS_F(w7 ,0x682e6ff3d6b2b8a3ULL)
    REF10_BLOCKS_F(w8 ,0x748f82ee5defb2fcULL)
    REF10_BLOCKS_F(w9 ,0x78a5636f43172f60ULL)
    REF10_BLOCKS_F(w10,0x84c87814a1f0ab72ULL)
    REF10_BLOCKS_F(w11,0x8cc702081a6439ecULL)
    REF10_BLOCKS_F(w12,0x90befffa23631e28ULL)
    REF10_BLOCKS_F(w13,0xa4506cebde82bde9ULL)
    REF10_BLOCKS_F(w14,0xbef9a3f7b2c67915ULL)
    REF10_BLOCKS_F(w15,0xc67178f2e372532bULL)

    REF10_EXPAND

    REF10_BLOCKS_F(w0 ,0xca273eceea26619cULL)
    REF10_BLOCKS_F(w1 ,0xd186b8c721c0c207ULL)
    REF10_BLOCKS_F(w2 ,0xeada7dd6cde0eb1eULL)
    REF10_BLOCKS_F(w3 ,0xf57d4f7fee6ed178ULL)
    REF10_BLOCKS_F(w4 ,0x06f067aa72176fbaULL)
    REF10_BLOCKS_F(w5 ,0x0a637dc5a2c898a6ULL)
    REF10_BLOCKS_F(w6 ,0x113f9804bef90daeULL)
    REF10_BLOCKS_F(w7 ,0x1b710b35131c471bULL)
    REF10_BLOCKS_F(w8 ,0x28db77f523047d84ULL)
    REF10_BLOCKS_F(w9 ,0x32caab7b40c72493ULL)
    REF10_BLOCKS_F(w10,0x3c9ebe0a15c9bebcULL)
    REF10_BLOCKS_F(w11,0x431d67c49c100d4cULL)
    REF10_BLOCKS_F(w12,0x4cc5d4becb3e42b6ULL)
    REF10_BLOCKS_F(w13,0x597f299cfc657e2aULL)
    REF10_BLOCKS_F(w14,0x5fcb6fab3ad6faecULL)
    REF10_BLOCKS_F(w15,0x6c44198c4a475817ULL)

    a += state[0];
    b += state[1];
    c += state[2];
    d += state[3];
    e += state[4];
    f += state[5];
    g += state[6];
    h += state[7];
  
    state[0] = a;
    state[1] = b;
    state[2] = c;
    state[3] = d;
    state[4] = e;
    state[5] = f;
    state[6] = g;
    state[7] = h;

    in += 128;
    inlen -= 128;
  }

  REF10_store_bigendian(statebytes +  0,state[0]);
  REF10_store_bigendian(statebytes +  8,state[1]);
  REF10_store_bigendian(statebytes + 16,state[2]);
  REF10_store_bigendian(statebytes + 24,state[3]);
  REF10_store_bigendian(statebytes + 32,state[4]);
  REF10_store_bigendian(statebytes + 40,state[5]);
  REF10_store_bigendian(statebytes + 48,state[6]);
  REF10_store_bigendian(statebytes + 56,state[7]);

  return 0;
}
