#include "ruby.h"
#include <stdlib.h>
#include <time.h>
#include "certificate.h"

static VALUE t_init(VALUE self){
  return self;
}

static VALUE t_generate_certificate(VALUE self, VALUE csr, VALUE valid, VALUE ca_key){
  //unsigned int id = rand();
  //char cname[CNAME_MAX_SIZE];
  //unsigned char auth_key[SMQV_PKEY_SIZE];
  //unsigned char token_pkey[MSS_PKEY_SIZE];
  //unsigned char token_skey[MSS_SKEY_SIZE];
  //char csr_[CSR_MAX_SIZE];
  //generate_csr(id, cname, auth_key, token_pkey, token_skey, csr_);
  //char certificate[CERTIFICATE_MAX_SIZE]; // saida
  //generate_certificate(csr, valid, ca_skey, certificate);
  //printf("%s\n", csr);
  return Qtrue;
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

VALUE cCertificateWrapper;

void Init_certificate_wrapper() {
  cCertificateWrapper = rb_define_class("CertificateWrapper", rb_cObject);
  rb_define_method(cCertificateWrapper, "initialize", t_init, 0);
  rb_define_singleton_method(cCertificateWrapper, "generate_certificate", t_generate_certificate, 3);
  rb_define_singleton_method(cCertificateWrapper, "ecdsa_keygen", t_ecdsa_keygen, 0);
}
