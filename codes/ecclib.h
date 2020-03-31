#pragma once
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")
#include <openssl\sha.h>
#include <openssl\hmac.h>
#include <openssl\aes.h>
#include <openssl\ec.h>
#include <openssl\ecdh.h>
#include <openssl\evp.h>
#define NULL_SCHEME 0x00
#define PROFILE_A 0x01
#define PROFILE_B 0x02
#define EPH_KEY_LENGTH 32
#define MAC_TAG_LENGTH 8
#define MAX_INFO_LENGTH 3000

typedef unsigned char u8;

u8 HOME_PUBLIC_KEY_SET[256][32] = { 0 };
u8 HOME_PRIVATE_KEY_SET[256][32] = { 0 };

void handleError(int e)
{
	switch (e)
	{
	case 0:printf("Invalid mode.\n"); break;
	case 1:printf("Invalid input.\n"); break;
	case 2:printf("Unable to generate a EVP_PKEY* type value.\n"); break;
	case 3:printf("Unable to get the public key from a EVP_PKEY* type value.\n"); break;
	case 4:printf("Unable to transform an octet string to the private key of  a EC_KEY* type value.\n"); break;
	case 5:printf("Unable to get the group of a EC_KEY* type value.\n"); break;
	case 6:printf("Unable to generate a EC_POINT* type value.\n"); break;
	case 7:printf("Unable to execute a EC_POINT multiply.\n"); break;
	case 8:printf("Unable to set the public key of a EC_KEY* type value.\n"); break;
	case 9:printf("Unable to transform an octet string from the private key of  a EC_KEY* type value.\n"); break;
	case 10:printf("Unable to generate a EVP_PKEY context.\n"); break;
	case 11:printf("Unable to initiate a EVP_PKEY_keygen program.\n"); break;
	case 12:printf("Unable to generate a EVP_PKEY* type value.\n"); break;
	case 13:printf("Unable to generate a EC_KEY* type value by curve name.\n"); break;
	case 14:printf("Unable to generate the key pair of EC_KEY* type value.\n"); break;
	case 15:printf("Unable to generate a EVP_PKEY derive context.\n"); break;
	case 16:printf("Unable to set a peer EVP_PKEY.\n"); break;
	case 17:printf("Unable to derive a public shared secret.\n"); break;
	case 18:printf("Unable to execute the key derivation function.\n"); break;
	case 19:printf("Unable to generate a EVP_CIPHER context.\n"); break;
	case 20:printf("Unable to initiate a EVP_CIPHER program.\n"); break;
	case 21:printf("Unable to update a EVP_CIPHER program.\n"); break;
	case 22:printf("Unable to execute the HMAC function.\n"); break;
	case 23:printf("Unable to get the public key from a EC_KEY* type value.\n"); break;
	case 24:printf("Unable to generate a EC_GROUP* type value by curve name.\n"); break;
	case 25:printf("Unable to transform an octet string from the public key of a EC_POINT .\n"); break;
	case 26:printf("Unable to compute a ECDH shared secret.\n"); break;
	case 27:printf("Unable to generate a public key of the EVP_PKEY.\n"); break;
	case 28:printf("MAC_tags inconsistent.\n"); break;
	case 29:printf("Unable to generate a BIGNUM* type value.\n"); break;
	case 30:printf("Unable to generate a EC_POINT by compressed coordinates.\n"); break;
	case 31:printf("Unable to get the private key from a EVP_PKEY* type value.\n"); break;
	case 32:printf("Unable to generate a EVP_PKEY type value by private key.\n"); break;
	default:
		break;
	}
}

void display(const u8* buf, int buflen)
{
	for (int i = 0; i < buflen; i++) printf("%02x", buf[i]);
	printf("\n\n");
}

void NAI_encoder(const int* type, const u8* rid, const int* schid, const int* hnkey, const u8* ecckey, const u8* userid, const int* textlen, const u8* cip, const u8* mac, const u8* realm, u8* output) {}

void NAI_decoder(const u8* input, int* type, u8* rid, int* schid, int* hnkey, u8* ecckey, u8* userid, int* textlen, u8* cip, u8* mac, u8* realm) {}

int MSIN_BCD_encoder(const u8* msin,u8* msin_bcd,int* textlen)
{
	for (int i = 0; i < *textlen; i++)
	{
		if (i % 2 == 0) msin_bcd[i / 2] = 0x0F & (msin[i] - '0');
		else msin_bcd[i / 2] += 0xF0 & ((msin[i] - '0') << 4);
	}
	if (*textlen % 2 != 0)
	{
		msin_bcd[*textlen / 2] |= 0xF0;
	}
	*textlen = (*textlen + 1) / 2;
	return 1;
}

int MSIN_BCD_decoder(const u8* msin_bcd, u8* msin, int* textlen)
{
	for (int i = 0; i < *textlen * 2; i++)
	{
		if (i == *textlen * 2 - 1 && msin_bcd[i / 2] >> 4 == 0x0F) break;
		if (i % 2 == 0) msin[i] = (msin_bcd[i / 2] & 0x0F) + '0';
		else msin[i] = (msin_bcd[i / 2] >> 4) + '0';
	}
	if (msin_bcd[*textlen / 2] >> 4 == 0x0F) *textlen = *textlen * 2 - 1;
	else *textlen = *textlen * 2;
	return 1;
}

int Eph_key_generator(const int schid, void** UE_key)
{
	if (schid == NULL_SCHEME)
	{
		return 1;
	}
	else
	{
		if (schid == PROFILE_A)
		{
			*UE_key = EVP_PKEY_new();
			EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
			if (pctx == NULL) { handleError(10); return 0; }
			if (!EVP_PKEY_keygen_init(pctx)) { handleError(11); return 0; }
			if (!EVP_PKEY_keygen(pctx, (EVP_PKEY**)UE_key)) { handleError(12); return 0; }
			EVP_PKEY_CTX_free(pctx);

			//display
			u8 checkbuf[MAX_INFO_LENGTH];
			size_t keylen = EPH_KEY_LENGTH;

			if (!EVP_PKEY_get_raw_private_key((EVP_PKEY*)*UE_key, checkbuf, &keylen)) { handleError(31); return 0; }
			printf("Eph. Private Key:");
			display(checkbuf, (int)keylen);

			if (!EVP_PKEY_get_raw_public_key((EVP_PKEY*)*UE_key, checkbuf, &keylen)) { handleError(3); return 0; }
			printf("Eph. Public Key:");
			display(checkbuf, (int)keylen);

		}
		else if (schid == PROFILE_B)
		{
			*UE_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
			if (*UE_key == NULL) { handleError(13); return 0; }
			if (!EC_KEY_generate_key((EC_KEY*)*UE_key)) { handleError(14); return 0; }

			//display
			u8 checkbuf[MAX_INFO_LENGTH];
			if (!EC_KEY_priv2oct((EC_KEY*)*UE_key, checkbuf, EPH_KEY_LENGTH)) { handleError(9); return 0; }
			printf("Eph. Private Key:");
			display(checkbuf, EPH_KEY_LENGTH);

			const EC_GROUP *G = EC_KEY_get0_group((EC_KEY*)*UE_key);
			if (G == NULL) { handleError(5); return 0; }

			const EC_POINT* UE_public_key = EC_KEY_get0_public_key((EC_KEY*)*UE_key);
			if (UE_public_key == NULL) { handleError(23); return 0; }

			if (!EC_POINT_point2oct(G, UE_public_key, POINT_CONVERSION_COMPRESSED, checkbuf, 1 + EPH_KEY_LENGTH, NULL)) { handleError(25); return 0; }
			printf("Eph. Public Key:");
			display(checkbuf, 1 + EPH_KEY_LENGTH);
		}
		else
		{
			handleError(0);
			return 0;
		}
	}
	return 1;
}

int EVP_AES_128_CTR(const u8* enckey, const u8* ICB, const u8* plaintext, u8* ciphertext, int datalen)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) { handleError(19); return 0; }
	if (!EVP_CipherInit_ex(ctx, EVP_aes_128_ctr(), NULL, enckey, ICB, 1)) { handleError(20); return 0; }
	int outlen;
	if (!EVP_CipherUpdate(ctx, ciphertext, &outlen, plaintext, datalen)) { handleError(21); return 0; }
	int encLen = outlen;
	if (!EVP_CipherFinal(ctx, ciphertext + outlen, &outlen)) { handleError(22); return 0; }
	encLen += outlen;
	EVP_CIPHER_CTX_free(ctx);
	return encLen;
}

int HMAC_SHA_256(const u8* mackey, const u8* ciphertext, int datalen, u8* mactag)
{
	unsigned int mdlen = EPH_KEY_LENGTH;
	u8 outbuf[EPH_KEY_LENGTH];
	HMAC(EVP_sha256(), mackey, SHA256_DIGEST_LENGTH, ciphertext, datalen, outbuf, &mdlen);
	for (int i = 0; i < MAC_TAG_LENGTH; i++)
		mactag[i] = outbuf[i];
	return mdlen;
}

int SUPI_encryption(
	//input
	const int schid,
	const u8* home_public_key,
	const void* UE_key,
	const u8* plaintext,
	const int textlen,
	//output
	u8* UE_public_key,
	u8* ciphertext,
	u8* mac
)
{
	if (schid == NULL_SCHEME)
	{
		for (int i = 0; i < textlen; i++)
		{
			ciphertext[i] = plaintext[i];
		}
		return 1;
	}

	u8 sharedKey[EPH_KEY_LENGTH] = { 0 };
	u8 derivedKey[EPH_KEY_LENGTH * 2] = { 0 };

	if (schid == PROFILE_A)
	{
		size_t keylen = EPH_KEY_LENGTH;
		if (!EVP_PKEY_get_raw_public_key((EVP_PKEY*)UE_key, UE_public_key, &keylen)) { handleError(3); return 0; }
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY*)UE_key, NULL);
		if (ctx == NULL) { handleError(10); return 0; }
		if (!EVP_PKEY_derive_init(ctx)) { handleError(15); return 0; };
		EVP_PKEY* home_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, home_public_key, EPH_KEY_LENGTH);
		if (home_key == NULL) { handleError(2); return 0; }
		if (!EVP_PKEY_derive_set_peer(ctx, home_key)) { handleError(16); return 0; }
		if (!EVP_PKEY_derive(ctx, sharedKey, &keylen)) { handleError(17); return 0; }
		EVP_PKEY_CTX_free(ctx);
	}
	if (schid == PROFILE_B)
	{
		const EC_POINT* public_key = EC_KEY_get0_public_key((EC_KEY*)UE_key);
		if (public_key == NULL) { handleError(23); return 0; }
		EC_GROUP* G = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
		if (G == NULL) { handleError(24); return 0; }
		if (!EC_POINT_point2oct(G, public_key, POINT_CONVERSION_COMPRESSED, UE_public_key, 1 + EPH_KEY_LENGTH, NULL)) { handleError(25); return 0; }

		EC_POINT *home_key = EC_POINT_new(G);
		if (home_key == NULL) { handleError(6); return 0; }
		BIGNUM *x = BN_new();
		if (x == NULL) { handleError(29); return 0; }
		BN_bin2bn(home_public_key + 1, EPH_KEY_LENGTH, x);
		if (!EC_POINT_set_compressed_coordinates_GFp(G, home_key, x, int(home_public_key[0]) % 2, NULL)) { handleError(30); return 0; }
		BN_free(x);
		EC_GROUP_free(G);

		if (!ECDH_compute_key(sharedKey, EPH_KEY_LENGTH, home_key, (EC_KEY*)UE_key, NULL)) { handleError(26); return 0; }
	}

	printf("Eph. Shared Key:");
	display(sharedKey, EPH_KEY_LENGTH);
	int sinfolen = (schid == PROFILE_A) ? EPH_KEY_LENGTH : EPH_KEY_LENGTH + 1;
	if (!ECDH_KDF_X9_62(derivedKey, EPH_KEY_LENGTH * 2, sharedKey, EPH_KEY_LENGTH, UE_public_key, sinfolen, EVP_sha256())) { handleError(18); return 0; }
	printf("Eph. Enc. Key:");
	display(derivedKey, AES_BLOCK_SIZE);
	printf("ICB:");
	display(derivedKey + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
	printf("Eph. mac key:");
	display(derivedKey + AES_BLOCK_SIZE * 2, SHA256_DIGEST_LENGTH);

	if (!EVP_AES_128_CTR(derivedKey, derivedKey + AES_BLOCK_SIZE, plaintext, ciphertext, textlen)) return 0;
	printf("Cipher-text value:");
	display(ciphertext, textlen);

	u8 macbuf[EPH_KEY_LENGTH];
	if (!HMAC(EVP_sha256(),
		derivedKey + AES_BLOCK_SIZE * 2,
		SHA256_DIGEST_LENGTH,
		ciphertext,
		textlen,
		macbuf,
		NULL)) {
		handleError(22); return 0;
	}
	for (int i = 0; i < MAC_TAG_LENGTH; i++)
		mac[i] = macbuf[i];
	printf("MAC-tag value:");
	display(mac, MAC_TAG_LENGTH);

	return 1;
}

int SUCI_decryption(
	//input
	const int schid,
	const u8* UE_public_key,
	const u8* home_private_key,
	const u8* ciphertext,
	const int textlen,
	const u8* mac,
	//output
	u8* plaintext
)
{
	if (schid == NULL_SCHEME)
	{
		for (int i = 0; i < textlen; i++)
		{
			 plaintext[i] = ciphertext[i];
		}
		return 1;
	}

	unsigned char sharedKey[EPH_KEY_LENGTH] = { 0 };
	unsigned char derivedKey[EPH_KEY_LENGTH * 2] = { 0 };
	unsigned char xmac[EPH_KEY_LENGTH] = { 0 };

	if (schid == PROFILE_A)
	{
		EVP_PKEY* public_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, UE_public_key, EPH_KEY_LENGTH);
		if (public_key == NULL) { handleError(27); return 0; }
		EVP_PKEY* home_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, home_private_key, EPH_KEY_LENGTH);
		if (home_key == NULL) { handleError(32); return 0; }
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(home_key, NULL);
		if (ctx == NULL) { handleError(10); return 0; }
		if (!EVP_PKEY_derive_init(ctx)) { handleError(15); return 0; }
		if (!EVP_PKEY_derive_set_peer(ctx, public_key)) { handleError(16); return 0; }
		size_t keylen = EPH_KEY_LENGTH;
		if (!EVP_PKEY_derive(ctx, sharedKey, &keylen)) { handleError(17); return 0; }
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(public_key);
		EVP_PKEY_free(home_key);
	}
	if (schid == PROFILE_B)
	{
		EC_GROUP *G = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
		if (G == NULL) { handleError(24); return 0; }
		EC_POINT *public_key = EC_POINT_new(G);
		if (public_key == NULL) { handleError(6); return 0; }
		BIGNUM *x = BN_new();
		if (x == NULL) { handleError(29); return 0; }
		BN_bin2bn(UE_public_key + 1, EPH_KEY_LENGTH, x);
		if (!EC_POINT_set_compressed_coordinates_GFp(G, public_key, x, int(UE_public_key[0]) % 2, NULL)) { handleError(30); return 0; }
		BN_free(x);

		EC_KEY* home_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		if (!EC_KEY_oct2priv(home_key, home_private_key, EPH_KEY_LENGTH)) { handleError(4); return 0; }
		EC_POINT *pubKey = EC_POINT_new(G);
		if (pubKey == NULL) { handleError(6); return 0; }
		if (!EC_POINT_mul(G, pubKey, EC_KEY_get0_private_key(home_key), NULL, NULL, NULL)) { handleError(7); return 0; }
		if (!EC_KEY_set_public_key(home_key, pubKey)) { handleError(8); return 0; }
		EC_POINT_free(pubKey);
		EC_GROUP_free(G);

		if (!ECDH_compute_key(sharedKey, EPH_KEY_LENGTH, public_key, home_key, NULL)) { handleError(26); return 0; }
		EC_POINT_free(public_key);
	}

	int sinfolen = (schid == PROFILE_A) ? EPH_KEY_LENGTH : EPH_KEY_LENGTH + 1;
	if (!ECDH_KDF_X9_62(derivedKey, EPH_KEY_LENGTH * 2, sharedKey, EPH_KEY_LENGTH, UE_public_key, sinfolen, EVP_sha256())) { handleError(18); return 0; }

	if (!HMAC(EVP_sha256(),
		derivedKey + AES_BLOCK_SIZE * 2,
		SHA256_DIGEST_LENGTH,
		ciphertext,
		textlen,
		xmac,
		NULL)) {
		handleError(22); return 0;
	}

	bool flag = 1;
	for (int i = 0; i < MAC_TAG_LENGTH; i++)
		if (xmac[i] != mac[i])
		{
			flag = 0;
			break;
		}
	if (!flag)
	{
		handleError(28);
		return 0;
	}
	else printf("MAC-tag verified!\n\n");

	if (!EVP_AES_128_CTR(derivedKey, derivedKey + AES_BLOCK_SIZE, ciphertext, plaintext, textlen)) return 0;
	return 1;
}

int SICF(const u8* SUPI, u8* SUCI)
{
	int type;
	u8 rid[4];
	int schid;
	int hnkey;
	u8 userid[MAX_INFO_LENGTH];
	u8 realm[MAX_INFO_LENGTH];
	int textlen;
	u8 ecckey[EPH_KEY_LENGTH];
	u8 cip[MAX_INFO_LENGTH];
	u8 mac[EPH_KEY_LENGTH];

	NAI_decoder(SUPI, &type, rid, &schid, &hnkey, NULL, userid, &textlen, NULL, NULL,realm);
	void* UE_key;
	Eph_key_generator(schid, &UE_key);

	if (type == 0)
	{
		u8 msin_bcd[5];
		MSIN_BCD_encoder(userid, msin_bcd, &textlen);
		SUPI_encryption(schid, HOME_PUBLIC_KEY_SET[hnkey], UE_key, msin_bcd, textlen, ecckey, cip, mac);
	}
	else
	{
		SUPI_encryption(schid, HOME_PUBLIC_KEY_SET[hnkey], UE_key, userid, textlen, ecckey, cip, mac);
	}

	NAI_encoder(&type, rid, &schid, &hnkey, ecckey, NULL, &textlen, cip, mac, realm, SUCI);
	return 1;
}

int SIDF(const u8* SUCI, u8* SUPI)
{
	int type;
	u8 rid[4];
	int schid;
	int hnkey;
	u8 ecckey[EPH_KEY_LENGTH];
	u8 userid[MAX_INFO_LENGTH];
	int textlen;
	u8 cip[MAX_INFO_LENGTH];
	u8 mac[EPH_KEY_LENGTH];
	u8 realm[MAX_INFO_LENGTH];

	NAI_decoder(SUCI, &type, rid, &schid, &hnkey, ecckey, userid, &textlen, cip, mac, realm);

	u8 plaintext[MAX_INFO_LENGTH];
	SUCI_decryption(schid,ecckey,HOME_PRIVATE_KEY_SET[hnkey],cip,textlen,mac,plaintext);

	if (type == 0)
	{
		MSIN_BCD_decoder(plaintext, userid, &textlen);
		NAI_encoder(&type, rid, &schid, &hnkey, NULL, userid, &textlen, NULL, NULL, realm, SUPI);
	}
	else
	{
		NAI_encoder(&type, rid, &schid, &hnkey, NULL, plaintext, &textlen, NULL, NULL, realm, SUPI);
	}

	return 1;
}