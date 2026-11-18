/* SPDX-License-Identifier: MIT OR GPL-2.0-or-later
 * Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors */
/* C0F (Corpus-0mnia Forensics) helper common code: TSV escaping, UTC time, SHA-256, MD5, base64.
 * Re-implementations written for C0F; no external libraries. */
#ifndef C0F_COMMON_H
#define C0F_COMMON_H
#pragma GCC diagnostic ignored "-Wunused-function"
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

#define C0F_HELPER_VERSION "1.0"

/* Print s (len bytes) as one TSV field: \\ \t \n \r escaped, other non-printables as \xHH. */
static void tsv_put(FILE *f, const char *s, size_t len) {
  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c == '\\') fputs("\\\\", f);
    else if (c == '\t') fputs("\\t", f);
    else if (c == '\n') fputs("\\n", f);
    else if (c == '\r') fputs("\\r", f);
    else if (c < 0x20 || c == 0x7f) fprintf(f, "\\x%02x", c);
    else fputc(c, f);
  }
}
static void tsv_str(FILE *f, const char *s) { if (s) tsv_put(f, s, strlen(s)); }
/* fixed-size C char array that may lack a NUL */
static void tsv_fixed(FILE *f, const char *s, size_t max) { size_t n = strnlen(s, max); tsv_put(f, s, n); }

/* ISO-8601 UTC from seconds (+ optional nanoseconds, <0 = none). */
static void fmt_utc(char *out, size_t outlen, int64_t sec, long nsec) {
  time_t t = (time_t)sec; struct tm tm;
  if (!gmtime_r(&t, &tm)) { snprintf(out, outlen, "INVALID(%lld)", (long long)sec); return; }
  char b[40]; strftime(b, sizeof b, "%Y-%m-%dT%H:%M:%S", &tm);
  if (nsec >= 0) snprintf(out, outlen, "%s.%09ldZ", b, nsec); else snprintf(out, outlen, "%sZ", b);
}

/* ---------- SHA-256 ---------- */
typedef struct { uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t n; } sha256_ctx;
static const uint32_t K256[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
static void sha256_block(sha256_ctx *c, const uint8_t *p) {
  uint32_t w[64], a,b,d,e,f,g,h,cc,t1,t2;
  for (int i=0;i<16;i++) w[i]=(uint32_t)p[4*i]<<24|(uint32_t)p[4*i+1]<<16|(uint32_t)p[4*i+2]<<8|p[4*i+3];
  for (int i=16;i<64;i++){ uint32_t s0=ROR32(w[i-15],7)^ROR32(w[i-15],18)^(w[i-15]>>3), s1=ROR32(w[i-2],17)^ROR32(w[i-2],19)^(w[i-2]>>10); w[i]=w[i-16]+s0+w[i-7]+s1; }
  a=c->h[0];b=c->h[1];cc=c->h[2];d=c->h[3];e=c->h[4];f=c->h[5];g=c->h[6];h=c->h[7];
  for (int i=0;i<64;i++){ t1=h+(ROR32(e,6)^ROR32(e,11)^ROR32(e,25))+((e&f)^(~e&g))+K256[i]+w[i]; t2=(ROR32(a,2)^ROR32(a,13)^ROR32(a,22))+((a&b)^(a&cc)^(b&cc)); h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2; }
  c->h[0]+=a;c->h[1]+=b;c->h[2]+=cc;c->h[3]+=d;c->h[4]+=e;c->h[5]+=f;c->h[6]+=g;c->h[7]+=h;
}
static void sha256_init(sha256_ctx *c){ static const uint32_t iv[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}; memcpy(c->h,iv,32); c->len=0; c->n=0; }
static void sha256_update(sha256_ctx *c, const void *data, size_t len) {
  const uint8_t *p=data; c->len+=len;
  if (c->n){ size_t k=64-c->n; if(k>len)k=len; memcpy(c->buf+c->n,p,k); c->n+=k; p+=k; len-=k; if(c->n==64){sha256_block(c,c->buf); c->n=0;} }
  while (len>=64){ sha256_block(c,p); p+=64; len-=64; }
  if (len){ memcpy(c->buf,p,len); c->n=len; }
}
static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
  uint64_t bits=c->len*8; uint8_t pad=0x80, z=0; sha256_update(c,&pad,1);
  while (c->n!=56) sha256_update(c,&z,1);
  uint8_t l[8]; for(int i=0;i<8;i++) l[i]=(uint8_t)(bits>>(56-8*i)); sha256_update(c,l,8);
  for (int i=0;i<8;i++){ out[4*i]=c->h[i]>>24; out[4*i+1]=c->h[i]>>16; out[4*i+2]=c->h[i]>>8; out[4*i+3]=c->h[i]; }
}
static void hex_encode(const uint8_t *in, size_t n, char *out) { static const char *hx="0123456789abcdef"; for(size_t i=0;i<n;i++){out[2*i]=hx[in[i]>>4];out[2*i+1]=hx[in[i]&15];} out[2*n]=0; }

/* ---------- MD5 (only for legacy SSH fingerprints) ---------- */
typedef struct { uint32_t h[4]; uint64_t len; uint8_t buf[64]; size_t n; } md5_ctx;
static void md5_block(md5_ctx *c, const uint8_t *p) {
  static const uint32_t T[64]={0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
  0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
  0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
  0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
  static const int S[64]={7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
  uint32_t x[16],a=c->h[0],b=c->h[1],cc=c->h[2],d=c->h[3];
  for(int i=0;i<16;i++) x[i]=p[4*i]|(uint32_t)p[4*i+1]<<8|(uint32_t)p[4*i+2]<<16|(uint32_t)p[4*i+3]<<24;
  for(int i=0;i<64;i++){ uint32_t f; int g;
    if(i<16){f=(b&cc)|(~b&d);g=i;} else if(i<32){f=(d&b)|(~d&cc);g=(5*i+1)%16;} else if(i<48){f=b^cc^d;g=(3*i+5)%16;} else {f=cc^(b|~d);g=(7*i)%16;}
    uint32_t t=d; d=cc; cc=b; uint32_t s=a+f+T[i]+x[g]; b=b+((s<<S[i])|(s>>(32-S[i]))); a=t; }
  c->h[0]+=a;c->h[1]+=b;c->h[2]+=cc;c->h[3]+=d;
}
static void md5_init(md5_ctx *c){ c->h[0]=0x67452301;c->h[1]=0xefcdab89;c->h[2]=0x98badcfe;c->h[3]=0x10325476;c->len=0;c->n=0; }
static void md5_update(md5_ctx *c, const void *data, size_t len){ const uint8_t *p=data; c->len+=len;
  while(len){ size_t k=64-c->n; if(k>len)k=len; memcpy(c->buf+c->n,p,k); c->n+=k;p+=k;len-=k; if(c->n==64){md5_block(c,c->buf);c->n=0;} } }
static void md5_final(md5_ctx *c, uint8_t out[16]){ uint64_t bits=c->len*8; uint8_t pad=0x80,z=0; md5_update(c,&pad,1); while(c->n!=56) md5_update(c,&z,1);
  uint8_t l[8]; for(int i=0;i<8;i++) l[i]=(uint8_t)(bits>>(8*i)); md5_update(c,l,8);
  for(int i=0;i<4;i++){out[4*i]=c->h[i];out[4*i+1]=c->h[i]>>8;out[4*i+2]=c->h[i]>>16;out[4*i+3]=c->h[i]>>24;} }

/* ---------- base64 ---------- */
static int b64val(int ch){ if(ch>='A'&&ch<='Z')return ch-'A'; if(ch>='a'&&ch<='z')return ch-'a'+26; if(ch>='0'&&ch<='9')return ch-'0'+52; if(ch=='+')return 62; if(ch=='/')return 63; return -1; }
/* Decodes, skipping whitespace; stops at '=' or invalid char. Returns bytes written or -1 on invalid input. */
static long b64_decode(const char *in, size_t inlen, uint8_t *out, size_t outmax) {
  uint32_t acc=0; int bits=0; size_t o=0;
  for (size_t i=0;i<inlen;i++){ int ch=(unsigned char)in[i];
    if (ch==' '||ch=='\n'||ch=='\r'||ch=='\t') continue;
    if (ch=='=') break;
    int v=b64val(ch); if(v<0) return -1;
    acc=(acc<<6)|(uint32_t)v; bits+=6;
    if(bits>=8){ bits-=8; if(o>=outmax) return -1; out[o++]=(uint8_t)(acc>>bits); }
  }
  return (long)o;
}
static void b64_encode_nopad(const uint8_t *in, size_t n, char *out) {
  static const char *t="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; size_t o=0;
  for (size_t i=0;i<n;i+=3){ uint32_t v=in[i]<<16; int k=1; if(i+1<n){v|=in[i+1]<<8;k++;} if(i+2<n){v|=in[i+2];k++;}
    out[o++]=t[(v>>18)&63]; out[o++]=t[(v>>12)&63]; if(k>1) out[o++]=t[(v>>6)&63]; if(k>2) out[o++]=t[v&63]; }
  out[o]=0;
}
#endif
