
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/objects.h>
#include <openssl/opensslconf.h>
#include <openssl/sm2.h>

#include <openssl/gm.h>

struct gm_key_st {
    EVP_PKEY* pkey;
    EC_KEY* ecKey;
	//BIGNUM* privatekeyBN;
    //BN_CTX* bnCtx;
    //EC_GROUP* group;
    //EC_POINT* pubpoint;
};

static int signSymbol(const EC_GROUP* ec_group, const EC_POINT* point, BN_CTX* ctx) {
	BIGNUM* px = BN_new();
    BIGNUM* py = BN_new();
	int ret = -1;
    if (!EC_POINT_get_affine_coordinates_GF2m(ec_group, point, px, py, ctx)) {
        goto end;
    }
	ret = BN_is_negative(py);
end:
	BN_free(px);
	BN_free(py);
	return ret;
}

EC_KEY* generateEckey(const EC_GROUP* group, const BIGNUM* privatekeyBN, const EC_POINT* pubpoint) {
	EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    if (ecKey == NULL) {
        return NULL;
    }

    if (1 != EC_KEY_set_group(ecKey, group) ) {
        goto error;
    }

	if (privatekeyBN != NULL) {
        if (1 != EC_KEY_set_private_key(ecKey, privatekeyBN)) {
            goto error;
        }
	}

    if (1 != EC_KEY_set_public_key(ecKey, pubpoint)) {
        goto error;
    }
	return ecKey;
error:
	EC_KEY_free(ecKey);
	return NULL;
}

static GM_KEY* deriveKeyFromEckey(EC_KEY* ecKey) {
    GM_KEY* gm_key = NULL;
    EVP_PKEY* pkey = NULL;
	EC_GROUP* group = NULL;

    group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
    if (group == NULL) {
        goto error;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        goto error;
    }

	if (1 != EVP_PKEY_set1_EC_KEY(pkey, ecKey)) {
        goto error;
    }

    gm_key = (GM_KEY*)malloc(sizeof(struct gm_key_st));
    if (gm_key == NULL) {
        goto error;
    }

    gm_key->pkey = pkey;
    gm_key->ecKey = ecKey;
    return gm_key;
error:
    EVP_PKEY_free(pkey);
	free(gm_key);
    return NULL;
}

GM_KEY* GMBytes2privateKey(const unsigned char* privatekey) {
    GM_KEY* gm_key = NULL;
	EVP_PKEY* pkey = NULL;
	BIGNUM* privatekeyBN = NULL;
	BN_CTX* bnCtx = NULL;
	EC_GROUP* group = NULL;
	EC_POINT* pubpoint = NULL;
	EC_KEY* ecKey = NULL;
	privatekeyBN = BN_bin2bn(privatekey, 32, NULL);
	if (privatekeyBN == NULL) {
		return NULL;
	}

	bnCtx = BN_CTX_new();
	if (bnCtx == NULL) {
		goto error;
	}

	group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
	if (group == NULL) {
		goto error;
	}

	pubpoint = EC_POINT_new(group);
	if (pubpoint == NULL) {
		goto error;
	}

	if ( 1 != EC_POINT_mul(group, pubpoint, privatekeyBN, NULL, NULL, bnCtx) ) {
		goto error;
	}

	ecKey = generateEckey(group, privatekeyBN, pubpoint);
	if (ecKey == NULL) {
		goto error;
	}

    pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		goto error;
	}

    if (1 != EVP_PKEY_set1_EC_KEY(pkey, ecKey)) {
		goto error;
	}

	gm_key = (GM_KEY*)malloc(sizeof(struct gm_key_st));
	if (gm_key == NULL) {
		goto error;
	}
	BN_CTX_free(bnCtx);

	gm_key->pkey = pkey;
    gm_key->ecKey = ecKey;
	//gm_key->privatekeyBN = privatekeyBN;
    //gm_key->group = group;
    //gm_key->pubpoint = pubpoint;

	return gm_key;
error:
	BN_CTX_free(bnCtx);
	if (ecKey != NULL) {
	    EC_KEY_free(ecKey);
	} else {
	    BN_free(privatekeyBN);
	    EC_GROUP_free(group);
	    EC_POINT_free(pubpoint);
	}
	EVP_PKEY_free(pkey);
	return NULL;
}

void GMFreeKey(GM_KEY* gm_key) {
	//BN_free(gm_key->privatekeyBN);
    //BN_CTX_free(gm_key->bnCtx);
    //EC_GROUP_free(gm_key->group);
    //EC_POINT_free(gm_key->pubpoint);
	EVP_PKEY_free(gm_key->pkey);
    EC_KEY_free(gm_key->ecKey);
	free(gm_key);
}

int GMGetPublicKey(const GM_KEY* gm_key, unsigned char** p) {
	unsigned char *pp = NULL;
	if (gm_key == NULL || gm_key->pkey == NULL) {
		return -1;
	}
	int len = i2d_PublicKey(gm_key->pkey, &pp);
	if (pp != NULL) {
		*p = (unsigned char*)malloc(64);
		memcpy(*p, &pp[1], len - 1);
		free(pp);
		return len - 1;
	}
	return 0;
}

int GMGetPrivateKey(const GM_KEY* gm_key, unsigned char** p) {
	unsigned char *pp = NULL;
	if (gm_key == NULL || gm_key->pkey == NULL) {
		return -1;
	}
    int len = i2d_PrivateKey(gm_key->pkey, &pp);
	if (pp != NULL) {
		*p = (unsigned char*)malloc(32);
        memcpy(*p, &pp[7], 32);
		free(pp);
        return 32;
    }
    return 0;
}

GM_KEY* GMBytes2publicKey(const unsigned char* publickey) {
	BN_CTX* bnctx = NULL;
	EC_POINT* pubpoint = NULL;
	GM_KEY* gm_key = NULL;
    EVP_PKEY* pkey = NULL;
    EC_GROUP* group = NULL;
    EC_KEY* ecKey = NULL;

	unsigned char *buf = NULL;

    group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
	if (group == NULL) {
		goto error;
	}
	bnctx = BN_CTX_new();
	if (bnctx == NULL) {
		goto error;
	}
	//pubpoint = EC_POINT_bn2point(group, publickeyBN, NULL, bnctx);
	pubpoint = EC_POINT_new(group);
	if (pubpoint == NULL) {
		goto error;
	}

	buf = OPENSSL_malloc(65);
	if (buf == NULL) {
		goto error;
	}

	memcpy(&buf[1], publickey, 64);
	buf[0] = 0x04;

	if (!EC_POINT_oct2point(group, pubpoint, buf, 65, bnctx)) {
		goto error;
	}

	ecKey = generateEckey(group, NULL, pubpoint);
    if (ecKey == NULL) {
		goto error;
    }

	pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        goto error;
    }

    if (1 != EVP_PKEY_set1_EC_KEY(pkey, ecKey)) {
        goto error;
    }

    gm_key = (GM_KEY*)malloc(sizeof(struct gm_key_st));
    if (gm_key == NULL) {
        goto error;
    }

    BN_CTX_free(bnctx);
	OPENSSL_free(buf);

    gm_key->pkey = pkey;
    gm_key->ecKey = ecKey;
    //gm_key->privatekeyBN = NULL;
    //gm_key->bnCtx = bnctx;
    //gm_key->group = group;
    //gm_key->pubpoint = pubpoint;
    return gm_key;
error:
    BN_CTX_free(bnctx);
	if (ecKey != NULL) {
        EC_KEY_free(ecKey);
	} else {
        EC_GROUP_free(group);
        EC_POINT_free(pubpoint);
	}
    EVP_PKEY_free(pkey);
	OPENSSL_free(buf);
    return NULL;
}

int GMEncrypt(const GM_KEY* gm_key, const unsigned char* in, const size_t inlen, unsigned char** out, size_t* outlen) {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(gm_key->pkey, NULL);
	if (ctx == NULL) {
		return -1;
	}
	int rv = EVP_PKEY_encrypt_init(ctx);
	if ( rv != 1) {
		goto error;
	}
	if (1 != EVP_PKEY_CTX_set_ec_scheme(ctx, NID_sm_scheme)) {
		goto error;
	}
	if (1 != EVP_PKEY_CTX_set_ec_encrypt_param(ctx, NID_sm3)) {
		goto error;
	}
	rv = EVP_PKEY_encrypt(ctx, NULL, (size_t*)outlen, in, inlen);
	if (rv != 1) {
		goto error;
	}

	*out = (unsigned char*)malloc(*outlen);
	if (*out == NULL) {
		goto error;
	}
	rv = EVP_PKEY_encrypt(ctx, *out, (size_t*)outlen, in, inlen);
	if (rv != 1) {
		free(*out);
		*out = NULL;
		*outlen = 0;
		goto error;
	}
	EVP_PKEY_CTX_free(ctx);
	return rv;
error:
	EVP_PKEY_CTX_free(ctx);
	return -1;
}

int GMDecrypt(const GM_KEY* gm_key, const unsigned char* in, const size_t inlen, unsigned char** out, size_t* outlen) {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(gm_key->pkey, NULL);
	if (ctx == NULL) {
		return -1;
	}
    int rv = EVP_PKEY_decrypt_init(ctx);
	if ( rv != 1 ) {
		goto error;
	}
    if ( 1 != EVP_PKEY_CTX_set_ec_scheme(ctx, NID_sm_scheme)) {
		goto error;
	}

    if (1 != EVP_PKEY_CTX_set_ec_encrypt_param(ctx, NID_sm3) ) {
		goto error;
	}
    rv = EVP_PKEY_decrypt(ctx, NULL, (size_t*)outlen, in, inlen);
    if (rv != 1) {
        goto error;
    }

    *out = (unsigned char*)malloc(*outlen);
    rv = EVP_PKEY_decrypt(ctx, *out, (size_t*)outlen, in, inlen);
	if (rv != 1) {
		free(*out);
		*out = NULL;
		*outlen = 0;
		goto error;
	}
	EVP_PKEY_CTX_free(ctx);
    return rv;
error:
	EVP_PKEY_CTX_free(ctx);
	return -1;
}

int GMSign(const GM_KEY* gm_key, const unsigned char* in, const size_t inlen, unsigned char ** out, size_t *outlen) {
    size_t size = 0;
	unsigned char *sig = NULL;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(gm_key->pkey, NULL);
    if (ctx == NULL) {
        return -1;
    }
	if (EVP_PKEY_sign_init(ctx) <= 0) {
		goto error;
	}

	if (EVP_PKEY_CTX_set_ec_scheme(ctx, NID_sm_scheme) <= 0) {
		goto error;
	}

	size = EVP_PKEY_size(gm_key->pkey);
	if (size <= 0) {
		goto error;
	}

    sig = (unsigned char *)malloc(size);
	if (sig == NULL) {
		goto error;
	}

	if (EVP_PKEY_sign(ctx, sig, &size, in, inlen) <= 0) {
		goto error;
	}
	EVP_PKEY_CTX_free(ctx);
	*out = sig;
	*outlen = size;
	return 1;
error:
	EVP_PKEY_CTX_free(ctx);
	free(sig);
    return -1;
}

int GMVerify(const GM_KEY* gm_key, const unsigned char* dgst, const size_t dgstlen, const unsigned char* sig, const size_t siglen) {
	int ret;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(gm_key->pkey, NULL);
    if (ctx == NULL) {
        return -1;
    }
    if (EVP_PKEY_verify_init(ctx) <= 0) {
        goto end;
    }

    if (EVP_PKEY_CTX_set_ec_scheme(ctx, NID_sm_scheme) <= 0) {
        goto end;
    }

	ret = EVP_PKEY_verify(ctx, sig, 64, dgst, dgstlen);
end:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

GM_KEY* GMRecoveryPublickey(const unsigned char* dgst, const size_t dgstlen, const unsigned char* sig, const size_t siglen) {
	EC_KEY* ecKey = SM2_recover_publickey(0, dgst, dgstlen, sig, siglen);
	if (ecKey == NULL) {
		return NULL;
	}
    return deriveKeyFromEckey(ecKey);
}

int GMDeriveKey(const GM_KEY* self, const GM_KEY* peer, unsigned char** out, size_t* len) {
	EVP_PKEY_CTX* ctx = NULL;
	unsigned char* buffer = NULL;
	int ret;
    ctx = EVP_PKEY_CTX_new(self->pkey, NULL);
	if (ctx == NULL) {
		return -1;
	}
    if (1 != EVP_PKEY_derive_init(ctx) ) {
		goto error;
	}

    if (1 != EVP_PKEY_derive_set_peer(ctx, peer->pkey)) {
		goto error;
	}

	size_t bufsize = 256;
	buffer = (unsigned char*)malloc(bufsize);
    ret = EVP_PKEY_derive(ctx, buffer, &bufsize);
    if (ret != 1) {
		goto error;
    }
	EVP_PKEY_CTX_free(ctx);
	*out = buffer;
	*len = bufsize;
	return ret;
error:
	EVP_PKEY_CTX_free(ctx);
	free(buffer);
	return -1;
}

static EVP_PKEY_CTX *new_pkey_keygen_ctx(const char *alg, ENGINE *e) {
    EVP_PKEY_CTX *ret = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *eng = NULL;
    int pkey_id;

    if (!(ameth = EVP_PKEY_asn1_find_str(&eng, alg, -1))) {
        return NULL;
    }
    EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL, ameth);
    ENGINE_finish(eng);
    if (!(ctx = EVP_PKEY_CTX_new_id(pkey_id, e))) {
        goto end;
    }
    ret = ctx;
    ctx = NULL;
end:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

GM_KEY* GMGeneratePrivateKey() {
	EVP_PKEY_CTX* pctx = NULL;
	EVP_PKEY* pkey = NULL;
	GM_KEY* gmkey = NULL;
	EC_KEY* ecKey = NULL;
	
	pctx = new_pkey_keygen_ctx("EC", NULL);
	if (pctx == NULL) {
		goto error;
	}
	if (1 != EVP_PKEY_keygen_init(pctx)) {
		goto error;
	}
    if (EVP_PKEY_CTX_ctrl_str(pctx, "ec_paramgen_curve", "sm2p256v1") <= 0) {
		goto error;
	}
	if (1 != EVP_PKEY_keygen(pctx, &pkey)) {
		goto error;
	}
    gmkey = (GM_KEY*)malloc(sizeof(struct gm_key_st));
	if (gmkey == NULL) {
		goto error;
	}
	EVP_PKEY_CTX_free(pctx);
	ecKey = EVP_PKEY_get1_EC_KEY(pkey);
	//privatekeyBN = EC_KEY_get0_private_key(ecKey);
	//group = EC_KEY_get0_group(ecKey);
	//pubpoint = EC_KEY_get0_public_key(ecKey);
	gmkey->pkey = pkey;
    gmkey->ecKey = ecKey;
    //gmkey->privatekeyBN = privatekeyBN;
    //gmkey->bnCtx = NULL;
    //gmkey->group = group;
    //gmkey->pubpoint = pubpoint;
	return gmkey;
error:
	//BN_free(privatekeyBN);
    //EC_GROUP_free(group);
    //EC_POINT_free(pubpoint);
	EVP_PKEY_CTX_free(pctx);
    EC_KEY_free(ecKey);
    EVP_PKEY_free(pkey);
	return NULL;
}

void GMPrintKey(const GM_KEY* gm_key, int type) {
	EVP_PKEY* pkey = gm_key->pkey;
    BIO* bio = BIO_new(BIO_s_mem());
    if (type == 0) {
        printf("--- this is private key ---\n");
        int ret = EVP_PKEY_print_private(bio, pkey, 0, NULL);
    } else {
        printf("--- this is public key ---\n");
        int ret = EVP_PKEY_print_public(bio, pkey, 0, NULL);
    }
    char* p = NULL;
    int len = BIO_get_mem_data(bio, &p);
    p[len-1] = '\0';
    printf("========%s=======\n", p);
	BIO_free(bio);
}

