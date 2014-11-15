#include "ntru.h"

#include <stdio.h>
#include "libntru/src/ntru.h"
#include "libntru/src/err.h"

void ntru_keygen(unsigned char *skey, unsigned char *pkey) {
	NtruEncParams params = EES613EP1;
	NtruEncKeyPair kp;
	NtruRandContext rand_ctx;
        NtruRandGen rng = NTRU_RNG_DEFAULT;
        ntru_rand_init(&rand_ctx, &rng);
	fprintf(stderr, "Generating Keypair..");
	do {
		fprintf(stderr, ".");
	} while(ntru_gen_key_pair(&params, &kp, &rand_ctx) != NTRU_SUCCESS);
	ntru_rand_release(&rand_ctx);
	printf(" done!\n");
}

void ntru_encryption(const unsigned char pkey[], const char *plaintext, unsigned char *ciphertext) {
}

void ntru_decryption(const unsigned char skey[], const unsigned char *ciphertext, char *plaintext) {
}

#ifdef NTRU_SELFTEST

int main() {
	unsigned char *skey, *pkey;
	ntru_keygen(skey, pkey);
	return 0;
}

#endif
