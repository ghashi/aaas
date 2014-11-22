#include "ruby.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "certificate.h"

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

VALUE cCertificateWrapper;

void Init_certificate_wrapper() {
  cCertificateWrapper = rb_define_class("CertificateWrapper", rb_cObject);
  rb_define_method(cCertificateWrapper, "initialize", t_init, 0);
  rb_define_singleton_method(cCertificateWrapper, "generate_certificate", t_generate_certificate, 3);
  rb_define_singleton_method(cCertificateWrapper, "ecdsa_keygen", t_ecdsa_keygen, 0);
}
