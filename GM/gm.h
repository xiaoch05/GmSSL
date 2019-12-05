
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct gm_key_st;
typedef struct gm_key_st GM_KEY;
GM_KEY* GMGeneratePrivateKey();

GM_KEY* GMBytes2privateKey(unsigned char* privatekey);
GM_KEY* GMBytes2publicKey(unsigned char* publickey);
void GMFreeKey(GM_KEY* pkey);

int GMGetPublicKey(GM_KEY* gm_key, unsigned char** p);
int GMGetPrivateKey(GM_KEY* gm_key, unsigned char** p);
int GMEncrypt(GM_KEY* gm_key, unsigned char* in, size_t inlen, unsigned char** out, size_t* outlen);
int GMDecrypt(GM_KEY* gm_key, unsigned char* in, size_t inlen, unsigned char** out, size_t* outlen);

int GMSign(GM_KEY* gm_key, unsigned char* in, size_t inlen, unsigned char ** out, size_t *outlen);
int GMVerify(GM_KEY* gm_key, unsigned char* dgst, size_t dgstlen, unsigned char* sig, size_t siglen);

int GMDeriveKey(GM_KEY* self, GM_KEY* peer, unsigned char** out, size_t* len);

GM_KEY* GMRecoveryPublickey(unsigned char* dgst, size_t dgstlen, unsigned char* sig, size_t siglen);

void GMPrintKey(GM_KEY* pkey, int type);

#ifdef __cplusplus
}
#endif
