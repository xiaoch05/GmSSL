
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct gm_key_st;
typedef struct gm_key_st GM_KEY;
GM_KEY* GMGeneratePrivateKey();

GM_KEY* GMBytes2privateKey(const unsigned char* privatekey);
GM_KEY* GMBytes2publicKey(const unsigned char* publickey);
void GMFreeKey(GM_KEY* pkey);

int GMGetPublicKey(const GM_KEY* gm_key, unsigned char** p);
int GMGetPrivateKey(const GM_KEY* gm_key, unsigned char** p);
int GMEncrypt(const GM_KEY* gm_key, const unsigned char* in, const size_t inlen, unsigned char** out, size_t* outlen);
int GMDecrypt(const GM_KEY* gm_key, const unsigned char* in, const size_t inlen, unsigned char** out, size_t* outlen);

int GMSign(const GM_KEY* gm_key, const unsigned char* in, const size_t inlen, unsigned char ** out, size_t *outlen);
int GMVerify(const GM_KEY* gm_key, const unsigned char* dgst, const size_t dgstlen, const unsigned char* sig, const size_t siglen);

int GMDeriveKey(const GM_KEY* self, const GM_KEY* peer, unsigned char** out, size_t* len);

GM_KEY* GMRecoveryPublickey(const unsigned char* dgst, const size_t dgstlen, const unsigned char* sig, const size_t siglen);

void GMPrintKey(const GM_KEY* pkey, int type);

#ifdef __cplusplus
}
#endif
