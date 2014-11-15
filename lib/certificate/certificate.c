#include "certificate.h"

#include "util.h"
#include "sponge.h"
#include <stdio.h>
#include <string.h>

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
void generate_csr(unsigned int id, char *cname, char time[ISO8601_TIME_SIZE], unsigned char auth_key[SMQV_PKEY_SIZE], unsigned char token_key[MSS_PKEY_SIZE], unsigned char csr_signature[MSS_SIGNATURE_SIZE], char csr[CSR_MAX_SIZE]) {
	unsigned int index = 0;
	unsigned char buffer[CSR_MAX_SIZE];
	memset(buffer, 0, CSR_MAX_SIZE);
	memset(csr, 0, CSR_MAX_SIZE);
	sprintf(buffer, "%u %s", id, cname);
	index += strlen(buffer);
	memcpy(buffer + index, time, ISO8601_TIME_SIZE);
	index += ISO8601_TIME_SIZE;
	memcpy(buffer + index, auth_key, SMQV_PKEY_SIZE);
	index += SMQV_PKEY_SIZE;
	memcpy(buffer + index, token_key, MSS_PKEY_SIZE);
	index += MSS_PKEY_SIZE;
	memcpy(buffer + index, csr_signature, MSS_SIGNATURE_SIZE);
	index += MSS_SIGNATURE_SIZE;
	base64encode(buffer, index, csr, CSR_MAX_SIZE);
}

void read_csr(unsigned int *id, char *cname, char time[ISO8601_TIME_SIZE], unsigned char auth_key[SMQV_PKEY_SIZE], unsigned char token_key[MSS_PKEY_SIZE], unsigned char csr_signature[MSS_SIGNATURE_SIZE], char csr[CSR_MAX_SIZE]) {
	unsigned int index = 0;
  int csr_size = CSR_MAX_SIZE;
	unsigned char buffer[CSR_MAX_SIZE];
	memset(buffer, 0, CSR_MAX_SIZE);
	base64decode(csr, strlen(csr), buffer, &csr_size);

  sscanf(buffer, "%u ", id);

  while(buffer[index++] !=  ' ');
  strcpy(cname, buffer + index);
  index += strlen(cname);
  memcpy(time, buffer + index, ISO8601_TIME_SIZE);
  index += ISO8601_TIME_SIZE;
  memcpy(auth_key, buffer + index, SMQV_PKEY_SIZE);
  index += SMQV_PKEY_SIZE;
  memcpy(token_key, buffer + index, MSS_PKEY_SIZE);
  index += MSS_PKEY_SIZE;
  memcpy(csr_signature, buffer + index, MSS_SIGNATURE_SIZE);
  index += MSS_SIGNATURE_SIZE;
}

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
void generate_certificate(
    char csr[CSR_MAX_SIZE],
    char certificate[CERTIFICATE_MAX_SIZE]) {
  unsigned int id;
  char *cname;
  char time[ISO8602_TIME_SIZE];
  char valid[ISO8601_TIME_SIZE];
  unsigned char auth_key[SMQV_PKEY_SIZE];
  unsigned char token_key[MSS_PKEY_SIZE];
  unsigned char signature[ECDSA_SIGNATURE_SIZE];
  unsigned char csr_signature[MSS_SIGNATURE_SIZE];
  unsigned int index = 0;
  unsigned char buffer[CERTIFICATE_MAX_SIZE];
  memset(buffer, 0, CERTIFICATE_MAX_SIZE);
  memset(csr, 0, CERTIFICATE_MAX_SIZE);
  sponge_state sponge[1];
  unsigned char csr_digest[CSR_DIGEST_LEN];

  read_csr(&id, cname, time, auth_key, token_key, csr_signature, csr);

  sponge_init(sponge);
  sponge_absorb(sponge, &id, sizeof(unsigned int));
  sponge_absorb(sponge, cname, sizeof(char)*strlen(cname));
  sponge_absorb(sponge, time, sizeof(char)*ISO8601_TIME_SIZE);
  sponge_absorb(sponge, auth_key, sizeof(unsigned char)*SMQV_PKEY_SIZE);
  sponge_absorb(sponge, token_key, sizeof(unsigned char)*MSS_PKEY_SIZE);
  sponge_absorb(sponge, csr_signature, sizeof(unsigned char)*MSS_SIGNATURE_SIZE);
  sponge_absorb(sponge, csr, sizeof(char)*CSR_MAX_SIZE);

  sponge_squeeze(sponge, csr_digest, CSR_DIGEST_LEN);

  base64encode(csr_digest, CSR_DIGEST_LEN, buffer, CERTIFICATE_MAX_SIZE);

  if(mss_verify(csr_signature, token_key, buffer)){
    sprintf(buffer, "%u %s", id, cname);
    index += strlen(buffer);
    memcpy(buffer + index, time, ISO8601_TIME_SIZE);
    index += ISO8601_TIME_SIZE;
    memcpy(buffer + index, valid, ISO8601_TIME_SIZE);
    index += ISO8601_TIME_SIZE;
    memcpy(buffer + index, auth_key, SMQV_PKEY_SIZE);
    index += SMQV_PKEY_SIZE;
    memcpy(buffer + index, token_key, MSS_PKEY_SIZE);
    index += MSS_PKEY_SIZE;
    memcpy(buffer + index, signature, ECDSA_SIGNATURE_SIZE);
    index += ECDSA_SIGNATURE_SIZE;

    base64encode(buffer, index, certificate, CERTIFICATE_MAX_SIZE);
  } else{
    printf("Authentication ERROR: !mss_verify\n");
  }

}

void read_certificate(
    unsigned int id,
    char *cname,
    char time[ISO8601_TIME_SIZE],
    char valid[ISO8601_TIME_SIZE],
    unsigned char auth_key[SMQV_PKEY_SIZE],
    unsigned char token_key[MSS_PKEY_SIZE],
    unsigned char signature[ECDSA_SIGNATURE_SIZE],
    char certificate[CERTIFICATE_MAX_SIZE]) {
  unsigned int index = 0;
  int certificate_size = CERTIFICATE_MAX_SIZE;
  unsigned char buffer[CERTIFICATE_MAX_SIZE];
  memset(buffer, 0, CERTIFICATE_MAX_SIZE);

  base64decode(certificate, strlen(certificate), buffer, &certificate_size);

  sscanf(buffer, "%u ", id);
  while(buffer[index++] !=  ' ');
  strcpy(cname, buffer + index);
  index += strlen(cname);
  memcpy(time, buffer + index, ISO8601_TIME_SIZE);
  index += ISO8601_TIME_SIZE;
  memcpy(valid, buffer + index, ISO8601_TIME_SIZE);
  index += ISO8601_TIME_SIZE;
  memcpy(auth_key, buffer + index, SMQV_PKEY_SIZE);
  index += SMQV_PKEY_SIZE;
  memcpy(token_key, buffer + index, MSS_PKEY_SIZE);
  index += MSS_PKEY_SIZE;
  memcpy(signature, buffer + index, ECDSA_SIGNATURE_SIZE);
  index += ECDSA_SIGNATURE_SIZE;
}
#ifdef CERTIFICATE_SELFTEST

#include <stdlib.h>
#include <time.h>

int main() {
	time_t t;
	srand((unsigned) time(&t));

  unsigned int id = rand(), i;
  char cname[100], time[ISO8601_TIME_SIZE], valid[ISO8601_TIME_SIZE], csr[CSR_MAX_SIZE], csr_cpy[CSR_MAX_SIZE], certificate[CERTIFICATE_MAX_SIZE], certificate_cpy[CERTIFICATE_MAX_SIZE];
  unsigned char auth_key[SMQV_PKEY_SIZE], token_key[MSS_PKEY_SIZE], csr_signature[MSS_SIGNATURE_SIZE], signature[ECDSA_SIGNATURE_SIZE];

	sprintf(cname, "TESTE do CERTIFICATE");

	for(i = 0; i < SMQV_PKEY_SIZE; i++)
		auth_key[i] = rand();
	for(i = 0; i < MSS_PKEY_SIZE; i++)
		token_key[i] = rand();
	for(i = 0; i < MSS_SIGNATURE_SIZE; i++)
		csr_signature[i] = rand();
	for(i = 0; i < ECDSA_SIGNATURE_SIZE; i++)
		signature[i] = rand();
	for(i = 0; i < CSR_MAX_SIZE; i++)
		csr[i] = rand();

  /**
   * CSR
   */
	generate_csr(id, cname, time, auth_key, token_key, csr_signature, csr);
	read_csr(&id, cname, time, auth_key, token_key, csr_signature, csr);
	generate_csr(id, cname, time, auth_key, token_key, csr_signature, csr_cpy);

	if(strcmp(csr, csr_cpy) == 0)
		printf("CSR generation/read - OK\n");
	else
		printf("CSR generation/read - Fail\n");
  printf("\n");

  /**
   * CERTIFICATE
   */
 generate_certificate(
    id,
    cname,
    time,
    valid,
    auth_key,
    token_key,
    signature,
    certificate);
  read_certificate(
    &id,
    cname,
    time,
    valid,
    auth_key,
    token_key,
    signature,
    certificate);
 generate_certificate(
    id,
    cname,
    time,
    valid,
    auth_key,
    token_key,
    signature,
    certificate_cpy);

	if(strcmp(certificate, certificate_cpy) == 0)
		printf("CERTIFICATE generation/read - OK\n");
	else
		printf("CERTIFICATE generation/read - Fail\n");
  printf("\n");

	return 0;
}

#endif
