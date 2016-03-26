#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stdint.h>

/****************************** MACROS ******************************/
#ifdef __cplusplus
extern "C" {
#endif
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

typedef struct {
	uint8_t data[64];
	uint32_t datalen;
	unsigned long long bitlen;
	uint32_t state[8];
} SHA256_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[]);

#ifdef __cplusplus
}
#endif
#endif   // SHA256_H
