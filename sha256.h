#pragma once

#include <stddef.h>
#include <stdint.h>

struct sha256_state {
	uint32_t state[8];
	uint64_t len;
	uint8_t final;
};

void sha256_init(struct sha256_state* state);
void sha256_process(struct sha256_state* state, const uint8_t* data, size_t len);
void sha256_final(struct sha256_state* state, const uint8_t* data, size_t length);

void sha256_hex(const struct sha256_state* state, char out[65]);
void sha256_bin(const struct sha256_state* state, uint8_t out[32]);
void sha256_b64(const struct sha256_state* state, char out[45]);

int sha256_b64_read(struct sha256_state* state, const char in[44]);
int sha256_hex_read(struct sha256_state* state, const char in[65]);
