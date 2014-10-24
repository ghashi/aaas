#include "ruby.h"
#include "util.h"
#include "mss.h"

static VALUE t_init(VALUE self){
  return self;
}


static VALUE t_verify(VALUE self, VALUE r_message, VALUE r_signature, VALUE r_key){
  unsigned char *message, *signature, *pkey;
  int message_len, signature_len, key_len;
  VALUE str;
  VALUE res = Qfalse;

  // convert VALUE to string for r_message, r_signature, r_key
  str = StringValue(r_message);
  message = RSTRING_PTR(str);
  message_len = RSTRING_LEN(str);
  str = StringValue(r_signature);
  signature = RSTRING_PTR(str);
  signature_len = RSTRING_LEN(str);
  str = StringValue(r_key);
  pkey = RSTRING_PTR(str);
  key_len = RSTRING_LEN(str);

  base64decode(message, message_len, message, &message_len);
  base64decode(signature, signature_len, signature, &signature_len);
  base64decode(pkey, key_len, pkey, &key_len);

  if(mss_verify(signature, pkey, message)){
    res = Qtrue;
  }
  return res;
}

VALUE cCryptoWrapper;

void Init_crypto_wrapper() {
  cCryptoWrapper = rb_define_class("CryptoWrapper", rb_cObject);
  rb_define_method(cCryptoWrapper, "initialize", t_init, 0);
  rb_define_singleton_method(cCryptoWrapper, "verify", t_verify, 3);
}
