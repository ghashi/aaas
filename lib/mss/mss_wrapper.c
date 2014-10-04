#include "ruby.h"
#include "include/mss.h"
#include "decodebase64.h"

static VALUE t_init(VALUE self)
{
  return self;
}

static VALUE t_verify(VALUE self, VALUE r_message, VALUE r_signature, VALUE r_key) {
  char *message, *signature, *key;
  int message_len, signature_len, key_len;
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

  printf("message %s %d\n", message, message_len);
  printf("signature %s %d\n", signature, signature_len);
  printf("key %s %d\n", key, key_len);
  base64decode(message, message_len, message, &message_len);
  base64decode(signature, signature_len, signature, &signature_len);
  base64decode(key, key_len, key, &key_len);
  printf("\nmessage %s %d\n", message, message_len);
  printf("signature %s %d\n", signature, signature_len);
  printf("key %s %d\n", key, key_len);

//
//unsigned char mss_verify(struct mss_node authpath[MSS_HEIGHT], const unsigned char *v, const char *M, unsigned short len,
//                         mmo_t *mmo, dm_t *f, unsigned char *h, unsigned short leaf_index, const unsigned char *sig,
//                         unsigned char *x, struct mss_node *currentLeaf, unsigned char merklePubKey[NODE_VALUE_SIZE]);

  /* Auxiliary varibles */
  struct mss_node node[3];
  unsigned char hash[LEN_BYTES(WINTERNITZ_N)];
  unsigned char signature[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)];
  unsigned char aux[LEN_BYTES(WINTERNITZ_SEC_LVL)];
  mmo_t hash_mmo;
  dm_t hash_dm;
  /* Merkle-tree variables */
  struct mss_node authpath[MSS_HEIGHT];
  unsigned char pkey[NODE_VALUE_SIZE];
  /* Initialization of Merkle–Damgård hash */
  DM_init(&hash_dm);
  /* Initialization of Winternitz-MMO OTS */
  sinit(&hash_mmo, MSS_SEC_LVL);

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
