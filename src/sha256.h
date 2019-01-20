#ifndef SHA256_H
#define SHA256_H
#include <stdint.h>
#include <string.h>

typedef struct {
	uint32_t h[8], Nl, Nh, num;
	uint8_t  data[64];
} SHA256_CTX;

static const uint32_t K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define SHA256_K_SIZE (sizeof(K) / sizeof(*K))

static void tobe32(uint8_t* target, uint32_t value) {
	for (int i = 3; i >= 0; i--, value >>= 8)
		target[i] = value & 0xff;
}
static uint32_t getbe32(const uint8_t* target) {
	unsigned long result = 0;
	for (size_t i = 0; i < 4; i++)
		result = (result << 8) | (target[i] & 0xff);
	return result;
}
static void sha256_transform(SHA256_CTX* ctx, const void* buf) {
	uint32_t W[SHA256_K_SIZE], t0, t1, t;

	uint32_t S0 = ctx->h[0];
	uint32_t S1 = ctx->h[1];
	uint32_t S2 = ctx->h[2];
	uint32_t S3 = ctx->h[3];
	uint32_t S4 = ctx->h[4];
	uint32_t S5 = ctx->h[5];
	uint32_t S6 = ctx->h[6];
	uint32_t S7 = ctx->h[7];

	const uint8_t* p = buf;
	for (int i = 0; i < 16; i++, p += 4)
		W[i] = getbe32(p);

#define Ch(x, y, z) (z ^ (x & (y ^ z)))
#define Maj(x, y, z) (((x | y) & z) | (x & y))
#define S(x, y) (((x) >> (y)) | ((x) << (32 - (y))))
#define Sigma0(x) (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x) (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x) (S(x, 7) ^ S(x, 18) ^ ((x) >> 3))
#define Gamma1(x) (S(x, 17) ^ S(x, 19) ^ ((x) >> 10))
	for (unsigned i = 16; i < SHA256_K_SIZE; i++) {
		W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
	}

#define RND(a, b, c, d, e, f, g, h, i)                  \
	t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i]; \
	t1 = Sigma0(a) + Maj(a, b, c);                  \
	d += t0;                                        \
	h = t0 + t1;
	for (unsigned i = 0; i < SHA256_K_SIZE; ++i) {
		RND(S0, S1, S2, S3, S4, S5, S6, S7, i);
		t  = S7;
		S7 = S6;
		S6 = S5;
		S5 = S4;
		S4 = S3;
		S3 = S2;
		S2 = S1;
		S1 = S0;
		S0 = t;
	}
#undef RND
	ctx->h[0] += S0;
	ctx->h[1] += S1;
	ctx->h[2] += S2;
	ctx->h[3] += S3;
	ctx->h[4] += S4;
	ctx->h[5] += S5;
	ctx->h[6] += S6;
	ctx->h[7] += S7;
}

SHA256_CTX* SHA256_Init(SHA256_CTX* ctx) {
	ctx->Nl   = 0;
	ctx->Nh   = 0;
	ctx->num  = 0;
	ctx->h[0] = 0x6A09E667;
	ctx->h[1] = 0xBB67AE85;
	ctx->h[2] = 0x3C6EF372;
	ctx->h[3] = 0xA54FF53A;
	ctx->h[4] = 0x510E527F;
	ctx->h[5] = 0x9B05688C;
	ctx->h[6] = 0x1F83D9AB;
	ctx->h[7] = 0x5BE0CD19;
	return ctx;
}

SHA256_CTX* SHA256_Update(SHA256_CTX* ctx, const void* src, size_t count) {
	uint32_t new_count = (ctx->Nl + (count << 3)) & 0xffffffff;
	if (new_count < ctx->Nl) {
		ctx->Nh += 1;
	}
	ctx->Nl = new_count;
	while (count) {
		unsigned int this_step = 64 - ctx->num;
		if (this_step > count)
			this_step = count;
		memcpy(ctx->data + ctx->num, src, this_step);
		if (this_step + ctx->num < 64) {
			ctx->num += this_step;
			break;
		}
		src = (const unsigned char*)src + this_step;
		count -= this_step;
		ctx->num = 0;
		sha256_transform(ctx, ctx->data);
	}
	return ctx;
}

uint32_t SHA256_Final(SHA256_CTX* ctx, uint8_t* digest) {
	uint8_t finalcount[8];
	tobe32(finalcount + 0, ctx->Nh);
	tobe32(finalcount + 4, ctx->Nl);
	SHA256_Update(ctx, "\200", 1);
	if (ctx->num > 56) {
		SHA256_Update(ctx, "\0\0\0\0\0\0\0\0", 8);
	}
	memset(ctx->data + ctx->num, 0, 56 - ctx->num);
	ctx->num = 56;
	SHA256_Update(ctx, finalcount, sizeof(finalcount));
	for (int i = 0; digest && i < 8; i++) {
		tobe32(digest + 4 * i, ctx->h[i]);
	}
	return ctx->h[0];
}
#endif