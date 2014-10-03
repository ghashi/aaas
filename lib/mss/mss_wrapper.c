#include "ruby.h"
#include "include/mss.h"

static VALUE t_init(VALUE self)
{
  return self;
}

static VALUE t_verify(VALUE self, VALUE r_message, VALUE r_signature, VALUE r_key) {
  char *message;
  int message_len;
  char *signature;
  int signature_len;
  char *key;
  int key_len;
  VALUE str;

  // convert VALUE to string for r_message, r_signature, r_key
  str = StringValue(r_message);
  message = RSTRING_PTR(str);
  message_len = RSTRING_LEN(str);
  str = StringValue(r_signature);
  signature = RSTRING_PTR(str);
  signature_len = RSTRING_LEN(str);
  str = StringValue(r_key);
  key = RSTRING_PTR(str);
  key_len = RSTRING_LEN(str);

//
//unsigned char mss_verify(struct mss_node authpath[MSS_HEIGHT], const unsigned char *v, const char *M, unsigned short len,
//                         mmo_t *mmo, dm_t *f, unsigned char *h, unsigned short leaf_index, const unsigned char *sig,
//                         unsigned char *x, struct mss_node *currentLeaf, unsigned char merklePubKey[NODE_VALUE_SIZE]);

//#DECLARAR
//  mmo
//  f
//  *h
//  *x
//  currentLeaf
//
//#RECEBER
//  merklePubKey
//#sig
//    sig
//    authpath
//    *v
//#mensagem
//    leaf_index
//    *M
//    len

//  verify()
  return Qtrue;
}

VALUE cMssWrapper;

void Init_mss_wrapper() {
  cMssWrapper = rb_define_class("MssWrapper", rb_cObject);
  rb_define_method(cMssWrapper, "initialize", t_init, 0);
  rb_define_singleton_method(cMssWrapper, "verify", t_verify, 3);
}
