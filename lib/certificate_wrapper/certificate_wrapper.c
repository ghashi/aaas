#include "ruby.h"
#include <stdlib.h>
#include <time.h>
#include "certificate.h"

static VALUE t_init(VALUE self){
  return self;
}

static VALUE t_generate_certificate(VALUE self){
  unsigned int id = rand();
  char cname[CNAME_MAX_SIZE], csr[CSR_MAX_SIZE];
  unsigned char auth_key[SMQV_PKEY_SIZE], token_skey[MSS_SKEY_SIZE], token_pkey[MSS_PKEY_SIZE];
  generate_csr(id, cname, auth_key, token_pkey, token_skey, csr);
  printf("%s\n", csr);
  return Qtrue;
}

VALUE cCertificateWrapper;

void Init_certificate_wrapper() {
  cCertificateWrapper = rb_define_class("CertificateWrapper", rb_cObject);
  rb_define_method(cCertificateWrapper, "initialize", t_init, 0);
  rb_define_singleton_method(cCertificateWrapper, "generate_certificate", t_generate_certificate, 0);
}
