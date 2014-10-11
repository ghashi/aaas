#include "ruby.h"

static VALUE t_init(VALUE self){
  return self;
}


static VALUE t_verify(VALUE self, VALUE r_message, VALUE r_signature, VALUE r_key){
  char *message, *signature, *pkey_b64;
  int message_len, signature_len, key_len;
  VALUE str;

  /* Auxiliary varibles */
  struct mss_node node;
  unsigned char hash[LEN_BYTES(WINTERNITZ_N)];
  unsigned char ots[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)];
  unsigned char aux[LEN_BYTES(WINTERNITZ_SEC_LVL)];
  mmo_t hash_mmo;
  dm_t hash_dm;
  unsigned short index;

  /* Merkle-tree variables */
  struct mss_node authpath[MSS_HEIGHT];
  unsigned char pkey[NODE_VALUE_SIZE];

  // convert VALUE to string for r_message, r_signature, r_key
  str = StringValue(r_message);
  message = RSTRING_PTR(str);
  message_len = RSTRING_LEN(str);
  str = StringValue(r_signature);
  signature = RSTRING_PTR(str);
  signature_len = RSTRING_LEN(str);
  str = StringValue(r_key);
  pkey_b64 = RSTRING_PTR(str);
  key_len = RSTRING_LEN(str);

  base64decode(message, message_len, message, &message_len);
  base64decode(signature, signature_len, signature, &signature_len);
  base64decode(pkey_b64, key_len, pkey, &key_len);

  /* Initialization of Merkle–Damgård hash */
  DM_init(&hash_dm);
  /* Initialization of Winternitz-MMO OTS */
  sinit(&hash_mmo, MSS_SEC_LVL);

  deserialze(ots, &index, &node, authpath, signature, signature_len);
  if(mss_verify(authpath, node.value, message, message_len + 1, &hash_mmo, &hash_dm, hash, index, ots, aux, &node, pkey)){
    return Qtrue;
  }
  return Qfalse;
}

VALUE cCryptoWrapper;

void Init_crypto_wrapper() {
  cCryptoWrapper = rb_define_class("CryptoWrapper", rb_cObject);
  rb_define_method(cCryptoWrapper, "initialize", t_init, 0);
  rb_define_singleton_method(cCryptoWrapper, "verify", t_verify, 3);
}


