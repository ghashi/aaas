#include "ruby.h"
#include "util.h"
#include "mss.h"

static VALUE t_init(VALUE self){
  return self;
}

static VALUE t_verify_hmac(VALUE self, VALUE r_tag, VALUE r_msg, VALUE r_session_key){
  unsigned char *session_key;
  unsigned int  session_key_len;
  unsigned char *msg;
  unsigned int  msg_len;
  unsigned char *tag;
  unsigned int  tag_len;
  unsigned char res;
  char *decoded_session_key;
  int decoded_session_key_len;
  char *decoded_tag;
  int decoded_tag_len;
  VALUE str;

  // convert VALUE to string
  str = StringValue(r_session_key);
  session_key = RSTRING_PTR(str);
  session_key_len = RSTRING_LEN(str);
  str = StringValue(r_msg);
  msg = RSTRING_PTR(str);
  msg_len = RSTRING_LEN(str);
  str = StringValue(r_tag);
  tag = RSTRING_PTR(str);
  tag_len = RSTRING_LEN(str);

  decoded_session_key = malloc(session_key_len);
  decoded_session_key_len = session_key_len;
  decoded_tag = malloc(tag_len);
  decoded_tag_len = tag_len;

  base64decode(session_key, session_key_len, decoded_session_key, &decoded_session_key_len);
  base64decode(tag, tag_len, decoded_tag, &decoded_tag_len);

  res = verify_hmac( decoded_tag, msg, decoded_session_key);

  free(decoded_session_key);
  free(decoded_tag);

  if(res) return Qtrue;
  return Qfalse;
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
  rb_define_singleton_method(cCryptoWrapper, "verify_hmac", t_verify_hmac, 3);
  //rb_define_singleton_method(cCryptoWrapper, "decrypt", t_decrypt, 3);
}
