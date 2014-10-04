#include "ruby.h"
#include "mss.h"
#include "decodebase64.h"

static VALUE t_init(VALUE self) {
  return self;
}

void deserialize_mss_node(struct mss_node *node, const char buffer[], int *offset) {
  int i;

  node->height = buffer[*offset];
  *offset += 1;
  node->index = (unsigned short) (buffer[*offset] & 0xFF);
  *offset += 1;
  node->index |= ((buffer[*offset] << 8) & 0xFF);
  *offset += 1;

  for(i = 0; i < LEN_BYTES(MSS_SEC_LVL); i++) {
    node->value[i] = buffer[*offset];
    *offset += 1;
  }
}

void deserialze(unsigned char *ots, unsigned short *index, struct mss_node *v, struct mss_node authpath[MSS_HEIGHT], const char *signature, int signatura_size) {
  int i;
  int offset = 0;

  *index = (unsigned short) ((signature[offset++] & 0xFF) | ((signature[offset++] << 8) & 0xFF));
  deserialize_mss_node(v, signature, &offset);

  for(i = 0; i < MSS_HEIGHT; i++)
    deserialize_mss_node(&authpath[i], signature, &offset);

  for(i = 0; offset < signatura_size; offset++)
    ots[i++] = signature[offset];
}

static VALUE t_verify(VALUE self, VALUE r_message, VALUE r_signature, VALUE r_key) {
  char *message, *signature, *key;
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
  key = RSTRING_PTR(str);
  key_len = RSTRING_LEN(str);

  base64decode(message, message_len, message, &message_len);
  base64decode(signature, signature_len, signature, &signature_len);
  base64decode(key, key_len, key, &key_len);

  /* Initialization of Merkle–Damgård hash */
  DM_init(&hash_dm);
  /* Initialization of Winternitz-MMO OTS */
  sinit(&hash_mmo, MSS_SEC_LVL);

  deserialze(ots, &index, &node, authpath, signature, signature_len);
  if(mss_verify(authpath, node.value, message, strlen(message) + 1, &hash_mmo, &hash_dm, hash, index, signature, aux, &node, pkey)){
    printf("hahah");
    return Qtrue;
  }
  return Qfalse;
}

VALUE cMssWrapper;

void Init_mss_wrapper() {
  cMssWrapper = rb_define_class("MssWrapper", rb_cObject);
  rb_define_method(cMssWrapper, "initialize", t_init, 0);
  rb_define_singleton_method(cMssWrapper, "verify", t_verify, 3);
}
