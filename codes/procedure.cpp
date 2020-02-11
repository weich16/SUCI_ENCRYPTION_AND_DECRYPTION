//ENVIRONMENT: 
//IDE:Visual Studio 2017
//crypho lib:openssl 1.1.1
#include <openssl\sha.h>
#include <openssl\hmac.h>
#include<openssl\aes.h>
#include<openssl\ec.h>
#include<openssl\ecdh.h>
#include<openssl\evp.h>
#include <iostream>
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")
#pragma warning(disable:4996)
#define STDIN 1
#define ENCRYPTION 0
#define DECRYPTION 1
#define NULL_SCHEME 0
#define PROFILE_A 1
#define PROFILE_B 2
#define EPH_KEY_LENGTH 32
#define MAC_TAG_LENGTH 8
#define MAX_INFO_LENGTH 3000
using namespace std;

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
	case 28:printf("MAC_tags mismatch.\n"); break;
	case 29:printf("Unable to generate a BIGNUM* type value.\n"); break;
	case 30:printf("Unable to generate a EC_POINT by compressed coordinates.\n"); break;
	default:
		break;
	}
}

int display(unsigned char* buf, int buflen)
{
	for (int i = 0; i < buflen; i++) printf("%02x", buf[i]);
	printf("\n");
	return 0;
}

int str2byte(const unsigned char* str, unsigned char* byte_stream,int datalen)
{
	int tmp = 0;
	for (int i = 0; i < datalen * 2; i += 2)
	{
		tmp = 0;
		if (48 <= str[i] && str[i] <= 57) tmp += 16 * (int(str[i]) - 48);
		if (65 <= str[i] && str[i] <= 70) tmp += 16 * (int(str[i]) - 55);
		if (97 <= str[i] && str[i] <= 102) tmp += 16 * (int(str[i]) - 87);
		if (48 <= str[i+1] && str[i+1] <= 57) tmp += int(str[i+1]) - 48;
		if (65 <= str[i+1] && str[i+1] <= 70) tmp += int(str[i+1]) - 55;
		if (97 <= str[i+1] && str[i+1] <= 102) tmp += int(str[i+1]) - 87;
		byte_stream[i/2] = char(tmp);
	}
	return 1;
}

int dataReader(unsigned char* outBuf)
{
	char strBuf[MAX_INFO_LENGTH] = { 0 };
	cin.getline(strBuf, MAX_INFO_LENGTH);
	int datalen = (int)strlen((char*)strBuf) / 2;
	if (!str2byte((unsigned char*)strBuf, outBuf, datalen)) return 0;
	return datalen;
}

int KDF(unsigned char* sharedkey, unsigned char* derivedkey)
{
	return ECDH_KDF_X9_62(derivedkey, EPH_KEY_LENGTH*2, sharedkey, EPH_KEY_LENGTH, NULL, NULL, EVP_sha256());
}

int EVP_AES_128_CTR(unsigned char* enckey, unsigned char* ICB, unsigned char* plaintext, unsigned char* ciphertext, int datalen)
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

int HMAC_SHA_256(unsigned char* mackey, unsigned char* ciphertest,int datalen,unsigned char* mactag )
{
	unsigned int mdlen = MAX_INFO_LENGTH;
	HMAC(EVP_sha256(), mackey, SHA256_DIGEST_LENGTH, ciphertest, datalen, mactag, &mdlen);
	return mdlen;
}

int procedure(
	const int mode,
	const int profile,
	unsigned char* databuf,
	int* datalen,
	unsigned char* IObuf,
	int* IOlen,
	const void* UE_key,
	const void* home_key
)
{

	if (mode == ENCRYPTION)
	{
		if (profile == NULL_SCHEME)
		{
			*IOlen = *datalen;
			memcpy(IObuf, databuf, *IOlen);
			return 1;
		}

		unsigned char sharedKey[EPH_KEY_LENGTH + 4] = { 0 };
		unsigned char derivedKey[EPH_KEY_LENGTH * 2] = { 0 };

		if (profile == PROFILE_A)
		{
			*IOlen = *datalen + EPH_KEY_LENGTH + MAC_TAG_LENGTH;

			size_t keylen = EPH_KEY_LENGTH;
			if (!EVP_PKEY_get_raw_public_key((EVP_PKEY*)UE_key, IObuf, &keylen)) { handleError(3); return 0; }
			EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY*)UE_key, NULL);
			if (ctx == NULL) { handleError(10); return 0; }
			if (!EVP_PKEY_derive_init(ctx)) { handleError(15); return 0; };
			if (!EVP_PKEY_derive_set_peer(ctx, (EVP_PKEY*)home_key)) { handleError(16); return 0; }
			if (!EVP_PKEY_derive(ctx, sharedKey, &keylen)) { handleError(17); return 0; }
			EVP_PKEY_CTX_free(ctx);

			if (!KDF(sharedKey, derivedKey)) { handleError(18); return 0; }

			if (!EVP_AES_128_CTR(derivedKey, derivedKey + AES_BLOCK_SIZE, databuf, IObuf + EPH_KEY_LENGTH, *datalen)) return 0;

			if (!HMAC(EVP_sha256(),
				derivedKey + AES_BLOCK_SIZE * 2,
				SHA256_DIGEST_LENGTH,
				IObuf + EPH_KEY_LENGTH, 
				*datalen,
				IObuf + EPH_KEY_LENGTH + *datalen,
				NULL)) {
				handleError(22); return 0;
			}
		}

		if (profile == PROFILE_B)
		{
			*IOlen = *datalen + 1 + EPH_KEY_LENGTH + MAC_TAG_LENGTH;

			const EC_POINT* public_key = EC_KEY_get0_public_key((EC_KEY*)UE_key);
			if (public_key == NULL) { handleError(23); return 0; }
			EC_GROUP* G = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
			if (G == NULL) { handleError(24); return 0; }
			if (!EC_POINT_point2oct(G, public_key, POINT_CONVERSION_COMPRESSED, IObuf, 1 + EPH_KEY_LENGTH, NULL)) { handleError(25); return 0; }

			if (!ECDH_compute_key(sharedKey, EPH_KEY_LENGTH, EC_KEY_get0_public_key((EC_KEY*)home_key), (EC_KEY*)UE_key, NULL)) { handleError(26); return 0; }
			EC_GROUP_free(G);

			if (!KDF(sharedKey, derivedKey)) { handleError(18); return 0; }

			if (!EVP_AES_128_CTR(derivedKey, derivedKey + AES_BLOCK_SIZE, databuf, IObuf + 1 + EPH_KEY_LENGTH, *datalen)) return 0;

			if (!HMAC(EVP_sha256(),
				derivedKey + AES_BLOCK_SIZE * 2, 
				SHA256_DIGEST_LENGTH, 
				IObuf + 1 + EPH_KEY_LENGTH,
				*datalen, 
				IObuf + 1 + EPH_KEY_LENGTH + *datalen, 
				NULL)) {
				handleError(22); return 0;
			}

		}
	}

	if (mode == DECRYPTION)
	{
		if (profile == NULL_SCHEME)
		{
			*datalen = *IOlen;
			memcpy(databuf, IObuf, *datalen);
			return 1;
		}

		unsigned char sharedKey[EPH_KEY_LENGTH + 4] = { 0 };
		unsigned char derivedKey[EPH_KEY_LENGTH * 2] = { 0 };
		unsigned char MAC_tag[EPH_KEY_LENGTH] = { 0 };

		if (profile == PROFILE_A)
		{
			*datalen = *IOlen - EPH_KEY_LENGTH - MAC_TAG_LENGTH;

			EVP_PKEY* public_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, IObuf, EPH_KEY_LENGTH);
			if (public_key == NULL) { handleError(27); return 0; }
			EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY*)home_key, NULL);
			if (ctx == NULL) { handleError(10); return 0; }
			if (!EVP_PKEY_derive_init(ctx)) { handleError(15); return 0; }
			if (!EVP_PKEY_derive_set_peer(ctx, public_key)) { handleError(16); return 0; }
			size_t keylen = EPH_KEY_LENGTH;
			if (!EVP_PKEY_derive(ctx, sharedKey, &keylen)) { handleError(17); return 0; }
			EVP_PKEY_CTX_free(ctx);
			EVP_PKEY_free(public_key);

			if (!KDF(sharedKey, derivedKey)) { handleError(18); return 0; }

			if (!HMAC(EVP_sha256(), 
				derivedKey + AES_BLOCK_SIZE * 2, 
				SHA256_DIGEST_LENGTH, 
				IObuf +  EPH_KEY_LENGTH, 
				*datalen, 
				MAC_tag, 
				NULL)) {
				handleError(22); return 0;
			}
			if (!memcmp(MAC_tag, IOlen + EPH_KEY_LENGTH + *datalen, MAC_TAG_LENGTH))
			{
				handleError(28);
				return 0;
			}

			if (!EVP_AES_128_CTR(derivedKey, derivedKey + AES_BLOCK_SIZE, IObuf + EPH_KEY_LENGTH, databuf, *datalen)) return 0;
		}

		if (profile == PROFILE_B)
		{
			*datalen = *IOlen - 1 - EPH_KEY_LENGTH - MAC_TAG_LENGTH;

			EC_GROUP *G = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
			if (G == NULL) { handleError(24); return 0; }
			EC_POINT *public_key = EC_POINT_new(G);
			if (public_key == NULL) { handleError(6); return 0; }
			BIGNUM *x = BN_new();
			if (x == NULL) { handleError(29); return 0; }
			BN_bin2bn(IObuf + 1, EPH_KEY_LENGTH,x);
			if (!EC_POINT_set_compressed_coordinates_GFp(G, public_key, x, int(IObuf[0]) % 2, NULL)) { handleError(30); return 0; }
			BN_free(x);
			EC_GROUP_free(G);

			if (!ECDH_compute_key(sharedKey, EPH_KEY_LENGTH, public_key, (EC_KEY*)home_key, NULL)) { handleError(26); return 0; }
			EC_POINT_free(public_key);

			if (!KDF(sharedKey, derivedKey)) { handleError(18); return 0; }

			if (!HMAC(EVP_sha256(), 
				derivedKey + AES_BLOCK_SIZE * 2, 
				SHA256_DIGEST_LENGTH, 
				IObuf + 1 + EPH_KEY_LENGTH, 
				*datalen, 
				MAC_tag, 
				NULL)) {
				handleError(22); return 0;
			}

			if (!memcmp(MAC_tag, IOlen + 1 + EPH_KEY_LENGTH + *datalen, MAC_TAG_LENGTH))
			{
				handleError(28);
				return 0;
			}

			if (!EVP_AES_128_CTR(derivedKey, derivedKey + AES_BLOCK_SIZE, IObuf + 1 + EPH_KEY_LENGTH, databuf, *datalen)) return 0;

		}

	}

	return 1;
}

int keyGenerator(int io,int profile,void** UE_key,void** home_key)
{
	if (io == STDIN)
	{
		if (profile == NULL_SCHEME)
		{
			return 1;
		}
		else
		{
			unsigned char UE_key_buf[EPH_KEY_LENGTH] = { 0 };
			unsigned char home_key_buf[EPH_KEY_LENGTH] = { 0 };
			if (!dataReader(UE_key_buf)) { handleError(1); return 0; }
			if (!dataReader(home_key_buf)) { handleError(1); return 0; }

			if (profile == PROFILE_A)
			{
				*UE_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, UE_key_buf, EPH_KEY_LENGTH);
				*home_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, home_key_buf, EPH_KEY_LENGTH);
				if (*UE_key == NULL || *home_key == NULL) { handleError(2); return 0; }			
			}
			else if (profile == PROFILE_B)
			{
				*UE_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
				*home_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
				if (!EC_KEY_oct2priv((EC_KEY*)*UE_key, UE_key_buf, EPH_KEY_LENGTH)) { handleError(4); return 0; }
				if (!EC_KEY_oct2priv((EC_KEY*)*home_key, home_key_buf, EPH_KEY_LENGTH)) { handleError(4); return 0; }
				const EC_GROUP *G1 = EC_KEY_get0_group((EC_KEY*)*UE_key), *G2 = EC_KEY_get0_group((EC_KEY*)*home_key);
				if (G1==NULL || G2 == NULL) { handleError(5); return 0; }
				EC_POINT *pubKey1 = EC_POINT_new(G1), *pubKey2 = EC_POINT_new(G2);
				if (pubKey1 == NULL || pubKey2 == NULL) { handleError(6); return 0; }
				if (!EC_POINT_mul(G1, pubKey1, EC_KEY_get0_private_key((EC_KEY*)*UE_key), NULL, NULL, NULL)) { handleError(7); return 0; }
				if (!EC_POINT_mul(G2, pubKey2, EC_KEY_get0_private_key((EC_KEY*)*home_key), NULL, NULL, NULL)) { handleError(7); return 0; }
				if (!EC_KEY_set_public_key((EC_KEY*)*UE_key, pubKey1)) { handleError(8); return 0; }
				if (!EC_KEY_set_public_key((EC_KEY*)*home_key, pubKey2)) { handleError(8); return 0; }
				EC_POINT_free(pubKey1);
				EC_POINT_free(pubKey2);			
			}
			else
			{
				handleError(0);
				return 0;
			}
		}
	}
	else if (io == NULL)
	{
		if (profile == NULL_SCHEME)
		{
			return 1;
		}
		else
		{
			if (profile == PROFILE_A)
			{
				*UE_key = EVP_PKEY_new();
				*home_key = EVP_PKEY_new();
				EVP_PKEY_CTX *pctx1 = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
				EVP_PKEY_CTX *pctx2 = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
				if (pctx1 == NULL || pctx2 == NULL) { handleError(10); return 0; }
				if (!EVP_PKEY_keygen_init(pctx1)) { handleError(11); return 0; }
				if (!EVP_PKEY_keygen_init(pctx2)) { handleError(11); return 0; }
				if (!EVP_PKEY_keygen(pctx1, (EVP_PKEY**)UE_key)) { handleError(12); return 0; }
				if (!EVP_PKEY_keygen(pctx2, (EVP_PKEY**)home_key)) { handleError(12); return 0; }
				EVP_PKEY_CTX_free(pctx1);
				EVP_PKEY_CTX_free(pctx2);				
			}
			else if (profile == PROFILE_B)
			{
				*UE_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
				*home_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
				if (UE_key == NULL || home_key == NULL) { handleError(13); return 0; }
				if (!EC_KEY_generate_key((EC_KEY*)*UE_key)) { handleError(14); return 0; }
				if (!EC_KEY_generate_key((EC_KEY*)*home_key)){ handleError(14); return 0; }
			}
			else
			{
				handleError(0);
				return 0;
			}
		}
	}
	else
	{
	handleError(0);
	return 0;
	}	
	return 1;
}

int main()
{
	//test for encryption and decryption

	//choose profile ans IO
	int profile = PROFILE_B;
	int io = STDIN;

	//key generation
	void *UE_key, *home_key;
	if (!keyGenerator(io, profile, &UE_key, &home_key)) return 0;

	//encryption
	unsigned char plaintext[MAX_INFO_LENGTH] = { 0 };
	unsigned char IObuf[MAX_INFO_LENGTH] = { 0 };
	int datalen = dataReader(plaintext);
	if (datalen > MAX_INFO_LENGTH) { handleError(1); return 0; }
	int IOlen;
	if (!procedure(
		ENCRYPTION,
		profile,
		plaintext,
		&datalen,
		IObuf,
		&IOlen,
		UE_key,
		home_key
	)) return 0;

	//decryption
	unsigned char _plaintext[MAX_INFO_LENGTH] = { 0 };
	int _datalen;
	if (!procedure(
		DECRYPTION,
		profile,
		_plaintext,
		&_datalen,
		IObuf,
		&IOlen,
		UE_key,
		home_key
	)) return 0;

	//display
	display(_plaintext, _datalen);
	

	return 0;
}
