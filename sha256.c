#include "sha256.h"

#include <assert.h>
#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <x86intrin.h>

void sha256_init(struct sha256_state* state) {
	state->state[0] = 0x6a09e667;
	state->state[1] = 0xbb67ae85;
	state->state[2] = 0x3c6ef372;
	state->state[3] = 0xa54ff53a;
	state->state[4] = 0x510e527f;
	state->state[5] = 0x9b05688c;
	state->state[6] = 0x1f83d9ab;
	state->state[7] = 0x5be0cd19;
	state->len = 0;
	state->final = 0;
}

void sha256_block(const uint8_t block[64], uint32_t state[8]);
static void sha256_process_assembly(struct sha256_state* state, const uint8_t* data, size_t len) {
	assert(len % 64 == 0);
	state->len += len;

	while (len >= 64) {
		sha256_block(data, state->state);
		data += 64;
		len -= 64;
	}
}

static void sha256_process_sha_ni(struct sha256_state* state, const uint8_t* data, size_t len) {
	__m128i state0, state1;
	__m128i msg, tmp;
	__m128i msg0, msg1, msg2, msg3;
	__m128i state0s, state1s;
	const __m128i mask = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

	tmp = _mm_loadu_si128((const __m128i*)&state->state[0]);
	state1 = _mm_loadu_si128((const __m128i*)&state->state[4]);

	tmp = _mm_shuffle_epi32(tmp, 0xB1);          /* CDAB */
	state1 = _mm_shuffle_epi32(state1, 0x1B);    /* EFGH */
	state0 = _mm_alignr_epi8(tmp, state1, 8);    /* ABEF */
	state1 = _mm_blend_epi16(state1, tmp, 0xF0); /* CDGH */

	assert(len % 64 == 0);
	state->len += len;

	while (len >= 64) {
		state0s = state0;
		state1s = state1;

		/* Rounds 0-3 */
		msg = _mm_loadu_si128((const __m128i*)(data + 0));
		msg0 = _mm_shuffle_epi8(msg, mask);
		msg = _mm_add_epi32(msg0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
		state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

		/* Rounds 4-7 */
		msg1 = _mm_loadu_si128((const __m128i*)(data + 16));
		msg1 = _mm_shuffle_epi8(msg1, mask);
		msg = _mm_add_epi32(msg1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
		state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
		msg0 = _mm_sha256msg1_epu32(msg0, msg1);

		/* Rounds 8-11 */
		msg2 = _mm_loadu_si128((const __m128i*)(data + 32));
		msg2 = _mm_shuffle_epi8(msg2, mask);
		msg = _mm_add_epi32(msg2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
		state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
		msg1 = _mm_sha256msg1_epu32(msg1, msg2);

		/* Rounds 12-15 */
		msg3 = _mm_loadu_si128((const __m128i*)(data + 48));
		msg3 = _mm_shuffle_epi8(msg3, mask);
		msg = _mm_add_epi32(msg3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
		state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
		tmp = _mm_alignr_epi8(msg3, msg2, 4);
		msg0 = _mm_add_epi32(msg0, tmp);
		msg0 = _mm_sha256msg2_epu32(msg0, msg3);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
		msg2 = _mm_sha256msg1_epu32(msg2, msg3);

		/* Rounds 16-19 */
		msg = _mm_add_epi32(msg0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
		state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
		tmp = _mm_alignr_epi8(msg0, msg3, 4);
		msg1 = _mm_add_epi32(msg1, tmp);
		msg1 = _mm_sha256msg2_epu32(msg1, msg0);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
		msg3 = _mm_sha256msg1_epu32(msg3, msg0);

		/* Rounds 20-23 */
		msg = _mm_add_epi32(msg1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
		state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
		tmp = _mm_alignr_epi8(msg1, msg0, 4);
		msg2 = _mm_add_epi32(msg2, tmp);
		msg2 = _mm_sha256msg2_epu32(msg2, msg1);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
		msg0 = _mm_sha256msg1_epu32(msg0, msg1);

		/* Rounds 24-27 */
		msg = _mm_add_epi32(msg2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
		state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
		tmp = _mm_alignr_epi8(msg2, msg1, 4);
		msg3 = _mm_add_epi32(msg3, tmp);
		msg3 = _mm_sha256msg2_epu32(msg3, msg2);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
		msg1 = _mm_sha256msg1_epu32(msg1, msg2);

		/* Rounds 28-31 */
		msg = _mm_add_epi32(msg3, _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
		state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
		tmp = _mm_alignr_epi8(msg3, msg2, 4);
		msg0 = _mm_add_epi32(msg0, tmp);
		msg0 = _mm_sha256msg2_epu32(msg0, msg3);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
		msg2 = _mm_sha256msg1_epu32(msg2, msg3);

		/* Rounds 32-35 */
		msg = _mm_add_epi32(msg0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
		state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
		tmp = _mm_alignr_epi8(msg0, msg3, 4);
		msg1 = _mm_add_epi32(msg1, tmp);
		msg1 = _mm_sha256msg2_epu32(msg1, msg0);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
		msg3 = _mm_sha256msg1_epu32(msg3, msg0);

		/* Rounds 36-39 */
		msg = _mm_add_epi32(msg1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
		state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
		tmp = _mm_alignr_epi8(msg1, msg0, 4);
		msg2 = _mm_add_epi32(msg2, tmp);
		msg2 = _mm_sha256msg2_epu32(msg2, msg1);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
		msg0 = _mm_sha256msg1_epu32(msg0, msg1);

		/* Rounds 40-43 */
		msg = _mm_add_epi32(msg2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
		state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
		tmp = _mm_alignr_epi8(msg2, msg1, 4);
		msg3 = _mm_add_epi32(msg3, tmp);
		msg3 = _mm_sha256msg2_epu32(msg3, msg2);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
		msg1 = _mm_sha256msg1_epu32(msg1, msg2);

		/* Rounds 44-47 */
		msg = _mm_add_epi32(msg3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
		state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
		tmp = _mm_alignr_epi8(msg3, msg2, 4);
		msg0 = _mm_add_epi32(msg0, tmp);
		msg0 = _mm_sha256msg2_epu32(msg0, msg3);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
		msg2 = _mm_sha256msg1_epu32(msg2, msg3);

		/* Rounds 48-51 */
		msg = _mm_add_epi32(msg0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
		state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
		tmp = _mm_alignr_epi8(msg0, msg3, 4);
		msg1 = _mm_add_epi32(msg1, tmp);
		msg1 = _mm_sha256msg2_epu32(msg1, msg0);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
		msg3 = _mm_sha256msg1_epu32(msg3, msg0);

		/* Rounds 52-55 */
		msg = _mm_add_epi32(msg1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
		state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
		tmp = _mm_alignr_epi8(msg1, msg0, 4);
		msg2 = _mm_add_epi32(msg2, tmp);
		msg2 = _mm_sha256msg2_epu32(msg2, msg1);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

		/* Rounds 56-59 */
		msg = _mm_add_epi32(msg2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
		state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
		tmp = _mm_alignr_epi8(msg2, msg1, 4);
		msg3 = _mm_add_epi32(msg3, tmp);
		msg3 = _mm_sha256msg2_epu32(msg3, msg2);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

		/* Rounds 60-63 */
		msg = _mm_add_epi32(msg3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
		state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

		/* Combine state  */
		state0 = _mm_add_epi32(state0, state0s);
		state1 = _mm_add_epi32(state1, state1s);

		data += 64;
		len -= 64;
	}

	tmp = _mm_shuffle_epi32(state0, 0x1B);       /* FEBA */
	state1 = _mm_shuffle_epi32(state1, 0xB1);    /* DCHG */
	state0 = _mm_blend_epi16(tmp, state1, 0xF0); /* DCBA */
	state1 = _mm_alignr_epi8(state1, tmp, 8);    /* ABEF */

	_mm_storeu_si128((__m128i*)&state->state[0], state0);
	_mm_storeu_si128((__m128i*)&state->state[4], state1);
}

void sha256_process(struct sha256_state* state, const uint8_t* data, size_t len) {
	static unsigned int sha_ni_supported;

	if (sha_ni_supported == 0) {
		sha_ni_supported = __builtin_cpu_supports("sha") ? 1 : 2;
	}

	if (sha_ni_supported == 2)
		sha256_process_assembly(state, data, len);
	else
		sha256_process_sha_ni(state, data, len);
}

void sha256_final(struct sha256_state* state, const uint8_t* data, size_t length) {
	if (state->final) return;


	assert(length <= 64);

	uint8_t padded[128];
	memcpy(padded, data, length);
	padded[length] = 0x80;

	// msglen for padding in bits
	uint64_t msglen = htobe64((state->len + length) * 8);

	if (length + 1 + sizeof(uint64_t) <= 64) {
		memset(padded + length + 1, 0, 64 - length - 1 - sizeof(uint64_t));
		memcpy(padded + 64 - sizeof(uint64_t), &msglen, sizeof(uint64_t));
		sha256_process(state, padded, 64);
	} else {
		memset(padded + length + 1, 0, 128 - length - 1 - sizeof(uint64_t));
		memcpy(padded + 128 - sizeof(uint64_t), &msglen, sizeof(uint64_t));
		sha256_process(state, padded, 128);
	}
	state->final = 1;
}

void sha256_hex(const struct sha256_state* state, char out[65]) {
	snprintf(out, 65, "%08x%08x%08x%08x%08x%08x%08x%08x", state->state[0], state->state[1], state->state[2],
	         state->state[3], state->state[4], state->state[5], state->state[6], state->state[7]);
}

void sha256_bin(const struct sha256_state* state, uint8_t out[32]) {
	for (int i = 0; i < 8; i++) {
		uint32_t be = htobe32(state->state[i]);
		memcpy(out + i * 4, &be, sizeof(uint32_t));
	}
}

void sha256_b64(const struct sha256_state* state, char out[45]) {
	static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	uint8_t bin[33];
	sha256_bin(state, bin);
	bin[32] = '\0';
	for (int i = 0; i < 11; i++) {
		out[i * 4 + 0] = t[bin[i * 3 + 0] >> 2];
		out[i * 4 + 1] = t[(bin[i * 3 + 0] << 4 & 0x30) | bin[i * 3 + 1] >> 4];
		out[i * 4 + 2] = t[(bin[i * 3 + 1] << 2 & 0x3c) | bin[i * 3 + 2] >> 6];
		out[i * 4 + 3] = t[bin[i * 3 + 2] & 0x3f];
	}
	out[43] = '=';
	out[44] = '\0';
}

int sha256_b64_read(struct sha256_state* state, const char in[44]) {
	state->final = 1;

	static char t[128] = {
	/*00*/	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	/*16*/	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	/*32*/	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
	/*48*/	0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff,
	/*64*/	0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
	/*80*/	0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
	/*96*/	0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	/*112*/	0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff
	};

	uint8_t bin[33];
	for (int i = 0; i < 44; i++) {
		if (in[i] & 0x80) return 1;
	}

	for (int i = 0; i < 11; i++) {
		uint8_t a = t[(uint8_t)in[i*4+0]];
		uint8_t b = t[(uint8_t)in[i*4+1]];
		uint8_t c = t[(uint8_t)in[i*4+2]];
		uint8_t d = t[(uint8_t)in[i*4+3]];
		if (a == 0xff || b == 0xff || c == 0xff || d == 0xff) return 1;

		bin[i*3+0] = a<<2 | b>>4;
		bin[i*3+1] = b<<4 | c>>2;
		bin[i*3+2] = c<<6 | d;
	}

	for (int i = 0; i < 8; i++) {
		uint32_t be;
		memcpy(&be, bin + i * 4, sizeof(uint32_t));
		state->state[i] = be32toh(be);
	}

	return 0;
}

int sha256_hex_read(struct sha256_state* state, const char in[65]) {
	state->final = 1;
	return (sscanf(in, "%08x%08x%08x%08x%08x%08x%08x%08x", &state->state[0], &state->state[1], &state->state[2],
		&state->state[3], &state->state[4], &state->state[5], &state->state[6], &state->state[7]) == 8) ? 0 : 1;
}

#ifdef TEST_SHA256_MAIN
#include <unistd.h>
int main() {
	struct sha256_state s, s2, s3;
	char hex[65];
	char b64[45];

	sha256_init(&s);
	sha256_final(&s, NULL, 0);
	sha256_hex(&s, hex);
	if (strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")) {
		printf("FAILED test1: %s\n", hex);
		return 1;
	}

	if (sha256_hex_read(&s2, hex)) {
		printf("FAILED sha256_hex_read\n");
		return 1;
	}

	if (memcmp(s.state, s2.state, 4*8)) {
		printf("FAILED sha256_hex_read\n");
		return 1;
	}

	sha256_b64(&s, b64);
	if (strcmp(b64, "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")) {
		printf("FAILED Base64: %s\n", b64);
		return 1;
	}

	if (sha256_b64_read(&s3, b64)) {
		printf("FAILED sha256_b64_read\n");
		return 1;
	}

	if (memcmp(s.state, s3.state, 4*8)) {
		printf("FAILED sha256_b64_read\n");
		return 1;
	}

	sha256_init(&s);
	sha256_final(&s, (uint8_t*)"abc", 3);
	sha256_hex(&s, hex);
	if (strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")) {
		printf("FAILED test2: %s\n", hex);
		return 1;
	}

	sha256_init(&s);
	sha256_final(&s, (uint8_t*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
	sha256_hex(&s, hex);
	if (strcmp(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")) {
		printf("FAILED test3: %s\n", hex);
		return 1;
	}

	sha256_init(&s);
	sha256_final(&s, (uint8_t*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq1", 57);
	sha256_hex(&s, hex);
	if (strcmp(hex, "cbb143ed5e1ae1ea21653c91cde5c1be208e326ffea9013f98bcea239f214b5b")) {
		printf("FAILED test4: %s\n", hex);
		return 1;
	}

	sha256_init(&s);
	uint8_t buf[128];
	memset(buf, 'a', 128);
	int i = 1000000;
	while (i >= 128) {
		sha256_process(&s, buf, 128);
		i -= 128;
	}
	sha256_final(&s, buf, i);
	sha256_hex(&s, hex);
	if (strcmp(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")) {
		printf("FAILED test5: %s\n", hex);
		return 1;
	}

	return 0;
}

#endif
