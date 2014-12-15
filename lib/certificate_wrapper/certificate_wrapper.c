#include "ruby.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "certificate.h"
#include "cert_time.h"
#include "ntru.h"

#define NTRU_BUFFER_SIZE 100

static VALUE t_init(VALUE self){
  return self;
}

static VALUE t_generate_certificate(VALUE self, VALUE r_csr, VALUE r_valid, VALUE r_ca_skey){
  unsigned char *csr;
           char *valid;
  unsigned char *ca_skey;
  unsigned char certificate[CERTIFICATE_MAX_SIZE];
  unsigned int  csr_len;
  unsigned int  valid_len;
  unsigned int  ca_skey_len;
  VALUE str;

  str         = StringValue(r_csr);
  csr         = RSTRING_PTR(str);
  str         = StringValue(r_valid);
  valid       = RSTRING_PTR(str);
  str         = StringValue(r_ca_skey);
  ca_skey     = RSTRING_PTR(str);

  generate_certificate(csr, valid, ca_skey, certificate);
  return rb_str_new2(certificate);
}

static VALUE t_ecdsa_keygen(VALUE self){
  unsigned char skey[ECDSA_SKEY_SIZE];
  unsigned char pkey[ECDSA_PKEY_SIZE];
  unsigned char encoded_skey[2*ECDSA_SKEY_SIZE];
  unsigned char encoded_pkey[2*ECDSA_PKEY_SIZE];
  VALUE key_list = rb_ary_new();

  ecdsa_keygen(skey, pkey);
  base64encode(skey, ECDSA_PKEY_SIZE, encoded_skey, 2 * ECDSA_PKEY_SIZE);
  base64encode(pkey, ECDSA_PKEY_SIZE, encoded_pkey, 2 * ECDSA_PKEY_SIZE);

  rb_ary_push(key_list, rb_str_new2(encoded_skey));
  rb_ary_push(key_list, rb_str_new2(encoded_pkey));

  return key_list;
}

static VALUE t_ntru_keygen(VALUE self){
	unsigned char skey[NTRU_SKEY_SIZE];
  unsigned char pkey[NTRU_PKEY_SIZE];
  unsigned char encoded_skey[2*NTRU_SKEY_SIZE];
  unsigned char encoded_pkey[2*NTRU_PKEY_SIZE];
  VALUE key_list = rb_ary_new();

  ntru_keygen(skey, pkey);
  base64encode(skey, NTRU_PKEY_SIZE, encoded_skey, 2 * NTRU_PKEY_SIZE);
  base64encode(pkey, NTRU_PKEY_SIZE, encoded_pkey, 2 * NTRU_PKEY_SIZE);

  rb_ary_push(key_list, rb_str_new2(encoded_skey));
  rb_ary_push(key_list, rb_str_new2(encoded_pkey));

  return key_list;
}

static VALUE t_ntru_encrypt(VALUE self, VALUE r_pkey, VALUE r_plaintext){
  char *pkey;
  unsigned int  pkey_len;
	char *plaintext;
  unsigned char *encoded_ciphertext;
  unsigned int  encoded_ciphertext_len;
  unsigned char *decoded_pkey;
  unsigned int   decoded_pkey_len;
	char *ciphertext;
  NtruEncParams params = EES613EP1;
	unsigned short ciphertext_len = ntru_enc_len(&params);
  VALUE str;

  str       = StringValue(r_pkey);
  pkey      = RSTRING_PTR(str);
  pkey_len  = RSTRING_LEN(str);
  str       = StringValue(r_plaintext);
  plaintext = RSTRING_PTR(str);

  decoded_pkey_len = pkey_len;
  decoded_pkey = malloc(pkey_len);

  ciphertext_len = ntru_ciphertext_len();
  ciphertext = malloc(ciphertext_len);

  base64decode(pkey, pkey_len, decoded_pkey, &decoded_pkey_len);
  ntru_encryption(decoded_pkey, plaintext, ciphertext);

  encoded_ciphertext_len = 2 * ciphertext_len;
  encoded_ciphertext = malloc(encoded_ciphertext_len);

  base64encode(ciphertext, ciphertext_len, encoded_ciphertext, encoded_ciphertext_len);

  free(ciphertext);

  return rb_str_new2(encoded_ciphertext);
}

static VALUE t_ntru_decrypt(VALUE self, VALUE r_skey, VALUE r_ciphertext){
	char plaintext[NTRU_BUFFER_SIZE];
  char *ciphertext;
  unsigned int   ciphertext_len;
  char *skey;
  unsigned int   skey_len;
  unsigned char *decoded_skey;
  unsigned int   decoded_skey_len;
  unsigned char *decoded_ciphertext;
  unsigned int   decoded_ciphertext_len;
  VALUE str;

  str             = StringValue(r_skey);
  skey            = RSTRING_PTR(str);
  skey_len        = RSTRING_LEN(str);
  str             = StringValue(r_ciphertext);
  ciphertext      = RSTRING_PTR(str);
  ciphertext_len  = RSTRING_LEN(str);

  decoded_skey_len       = skey_len;
  decoded_skey           = malloc(skey_len);
  decoded_ciphertext_len = ciphertext_len;
  decoded_ciphertext     = malloc(ciphertext_len);

  base64decode(skey, skey_len, decoded_skey, &decoded_skey_len);
  base64decode(ciphertext, ciphertext_len, decoded_ciphertext, &decoded_ciphertext_len);

  ntru_decryption(decoded_skey, decoded_ciphertext, plaintext);

  return rb_str_new2(plaintext);
}

static VALUE t_get_csr_pkey(VALUE self, VALUE r_csr){
  unsigned char csr_pkey[MSS_PKEY_SIZE];
  char encoded_csr_pkey[2 * MSS_PKEY_SIZE];
  unsigned int id_cname_size;
  unsigned char *decoded_csr;
  unsigned int   decoded_csr_len;
  char *csr;
  unsigned int   csr_len;
  VALUE str;

  str            = StringValue(r_csr);
  csr            = RSTRING_PTR(str);
  csr_len  = RSTRING_LEN(str);

  decoded_csr_len = csr_len;
  decoded_csr     = malloc(csr_len);

  base64decode(csr, csr_len, decoded_csr, &decoded_csr_len);
  id_cname_size = strlen(decoded_csr);

  memcpy(csr_pkey, decoded_csr + id_cname_size + TIME_BUFFER_SIZE + SMQV_PKEY_SIZE + 1, MSS_PKEY_SIZE);

  base64encode(csr_pkey, MSS_PKEY_SIZE, encoded_csr_pkey, 2 * MSS_PKEY_SIZE);

  return rb_str_new2(encoded_csr_pkey);
}

VALUE cCertificateWrapper;

void Init_certificate_wrapper() {
  cCertificateWrapper = rb_define_class("CertificateWrapper", rb_cObject);
  rb_define_method(cCertificateWrapper, "initialize", t_init, 0);
  rb_define_singleton_method(cCertificateWrapper, "generate_certificate", t_generate_certificate, 3);
  rb_define_singleton_method(cCertificateWrapper, "get_csr_pkey", t_get_csr_pkey, 1);
  rb_define_singleton_method(cCertificateWrapper, "ecdsa_keygen", t_ecdsa_keygen, 0);
  rb_define_singleton_method(cCertificateWrapper, "ntru_keygen", t_ntru_keygen, 0);
  rb_define_singleton_method(cCertificateWrapper, "ntru_encrypt", t_ntru_encrypt, 2);
  rb_define_singleton_method(cCertificateWrapper, "ntru_decrypt", t_ntru_decrypt, 2);
}
