#ifndef __CERTIFICATE_H_
#define __CERTIFICATE_H_

/*
 *	CSR stands for certificate request, which is sent by the client (or gateway) in order to provide the info needed by the AAAS to generate the certificate.
 *
 *		CSR info:
 *				- id: requester identification
 *				- cname: common name
 *				- time: date on which the csr has been generated
 *				- auth_key: key used in mutual authentication (SMQV)
 *				- token_key: key used to sign access token (MSS)
 *				- csr_signature: CSR signature under token_key
 *
 */

#include "mss.h"
#include "ecdsa.h"

#define ISO8601_TIME_SIZE	25
#define SMQV_PKEY_SIZE		2 * 32	// Non-compressed form

#define CSR_MAX_SIZE		(2 * (MSS_SIGNATURE_SIZE + MSS_PKEY_SIZE + SMQV_PKEY_SIZE + ISO8601_TIME_SIZE + 40))
#define CSR_DIGEST_LEN		((2 * MSS_SEC_LVL) / 8)

#define CERTIFICATE_MAX_SIZE	(2 * (ECDSA_SIGNATURE_SIZE + MSS_PKEY_SIZE + SMQV_PKEY_SIZE + ISO8601_TIME_SIZE + 40))

#define CNAME_MAX_SIZE		100

/*
 *		Certificate info:
 *				- id: requester identification
 *				- cname: common name
 *				- time: date on which the certificate has been generated
 *				- valid: date up to the certificate is valid
 *				- auth_key: key used in mutual authentication (SMQV)
 *				- token_key: key used to sign access token (MSS)
 *				- signature: signature under issuer's key
 *
 */
void generate_csr(unsigned int id, char *cname, char time[ISO8601_TIME_SIZE], unsigned char auth_key[SMQV_PKEY_SIZE], unsigned char token_key[MSS_PKEY_SIZE], unsigned char mss_skey[MSS_SKEY_SIZE], char csr[CSR_MAX_SIZE]);
unsigned char read_csr(unsigned int *id, char *cname, char time[ISO8601_TIME_SIZE], unsigned char auth_key[SMQV_PKEY_SIZE], unsigned char token_key[MSS_PKEY_SIZE], unsigned char csr_signature[MSS_SIGNATURE_SIZE], char csr[CSR_MAX_SIZE]);

void generate_certificate(const unsigned char csr[CSR_MAX_SIZE], const char valid[ISO8601_TIME_SIZE], const unsigned char ca_skey[ECDSA_SKEY_SIZE], unsigned char certificate[CERTIFICATE_MAX_SIZE]);
unsigned char read_certificate(unsigned int *id, char *cname, char time[ISO8601_TIME_SIZE], char valid[ISO8601_TIME_SIZE], unsigned char auth_key[SMQV_PKEY_SIZE], unsigned char token_key[MSS_PKEY_SIZE], unsigned char cert_signature[ECDSA_SIGNATURE_SIZE], const unsigned char ca_pkey[ECDSA_PKEY_SIZE], const unsigned char certificate[CERTIFICATE_MAX_SIZE]);

#endif // __CERTIFICATE_H_
