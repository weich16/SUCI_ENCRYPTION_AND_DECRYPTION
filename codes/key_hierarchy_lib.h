#pragma once
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")
#include <openssl\evp.h>
#include <openssl\sha.h>
#include <openssl\hmac.h>
#define MAX_LEN 1024

int HMAC_SHA_256(
	const unsigned char* mackey, 
	const unsigned char* ciphertext, 
	const unsigned int datalen, 
	unsigned char* mactag,
	const unsigned int maclen
)
{
	unsigned char outbuf[256];
	HMAC(
		EVP_sha256(), 
		mackey, 
		SHA256_DIGEST_LENGTH, 
		ciphertext, 
		datalen, 
		outbuf, 
		NULL
	);
	memcpy(mactag, outbuf, maclen);
	return maclen;
}

int PRF_new(
	const unsigned char* KEY,
	const unsigned char* S,
	unsigned char* MK
)
{
	int len = strlen((const char*)S);
	int counts = (len % 32 == 0) ? len / 32 : len / 32 + 1;
	unsigned char T[MAX_LEN] = { 0 };
	for (int i = 0; i < counts; i++)
	{
		if (i == 0)
		{
			memcpy(T, S, len);
			T[len] = 1;
		}
		else
		{
			memcpy(T + 32, S, len);
			T[32 + len] = i + 1;
		}

		HMAC(
			EVP_sha256(),
			KEY,
			SHA256_DIGEST_LENGTH,
			T,
			(i == 0) ? len + 1 : 32 + len + 1,
			T,
			NULL
		);

		memcpy(MK + i * 32, T, 32);
	}
	return 1;
}

int Universal_key_generator(
	const unsigned char FC,
	const unsigned char* KEY,
	const unsigned char* P0,
	const unsigned char* P1,
	const unsigned char* P2,
	unsigned char* outbuf
)
{
	unsigned char S[MAX_LEN] = { 0 };
	S[0] = FC;
	unsigned short L0 = strlen((const char*)P0);
	memcpy(S + 1, P0, L0);
	S[1 + L0] = L0 >> 8;
	S[1 + L0 + 1] = L0 & 0xFF;
	if (P1 != NULL)
	{
		unsigned short L1 = strlen((const char*)P1);
		L1 = (L1 == 0) ? 1 : L1;
		memcpy(S + 1 + L0 + 2, P1, L1);
		S[1 + L0 + 2 + L1] = L1 >> 8;
		S[1 + L0 + 2 + L1 + 1] = L1 & 0xFF;
		if (P2 != NULL)
		{
			unsigned short L2 = strlen((const char*)P2);
			L2 = (L2 == 0) ? 1 : L2;
			memcpy(S + 1 + L0 + 2 + L1 + 2, P2, L2);
			S[1 + L0 + 2 + L1 + 2 + L2] = L2 >> 8;
			S[1 + L0 + 2 + L1 + 2 + L2 + 1] = L2 & 0xFF;
			HMAC_SHA_256(KEY, S, L0 + L1 + L2 + 7, outbuf, 32);
		}
		else HMAC_SHA_256(KEY, S, L0 + L1 + 5, outbuf, 32);
	}
	else HMAC_SHA_256(KEY, S, L0 + 3, outbuf, 32);
	
	return 1;
}

//33.501 A.2
int Kausf_5G_AKA_generator(
	const unsigned char* CKIK,
	const unsigned char* SNname,
	const unsigned char* SQN_xor_AK,
	unsigned char* Kausf
)
{
	Universal_key_generator(0x6A, CKIK, SNname, SQN_xor_AK, NULL, Kausf);
	return 1;
}

//33.501 A.3
int CKIK_new_generator(
	const unsigned char* CKIK,
	const unsigned char* SNname,
	const unsigned char* SQN_xor_AK,
	unsigned char* CK_new,
	unsigned char* IK_new
)
{
	unsigned char outbuf[32];
	Universal_key_generator(0x20, CKIK, SNname, SQN_xor_AK, NULL, outbuf);
	memcpy(CK_new, outbuf, 16);
	memcpy(IK_new, outbuf + 16, 16);
	return 1;
}

//rfc 5448
int MK_EAP_AKA_new_generator(
	const unsigned char* CK_new,
	const unsigned char* IK_new,
	const unsigned char* Identity,
	unsigned char* MK
)
{
	unsigned char KEY[32] = { 0 };
	memcpy(KEY, IK_new, 16);
	memcpy(KEY + 16, CK_new, 16);

	unsigned char S[MAX_LEN] = { 0 };
	memcpy(S, "EAP-AKA'", 8);
	unsigned short L1 = strlen((const char*)Identity);
	memcpy(S + 8, Identity, L1);

	PRF_new(KEY, S, MK);
	return 1;
}

//rfc 5448
int Kset_EAP_AKA_new_generator(
	const unsigned char* MK,
	unsigned char* K_encr,
	unsigned char* K_aut,
	unsigned char* K_re,
	unsigned char* MSK,
	unsigned char* EMSK,
	unsigned char* Kausf
)
{
	memcpy(K_encr, MK, 16);
	memcpy(K_aut, MK + 16, 32);
	memcpy(K_re, MK + 48, 32);
	memcpy(MSK, MK + 80, 64);
	memcpy(EMSK, MK + 144, 64);
	memcpy(Kausf, EMSK, 32);
	return 1;
}

//33.501 A.4
int RES_star_generator(
	const unsigned char* CKIK,
	const unsigned char* SNname,
	const unsigned char* RAND,
	const unsigned char* RES,
	unsigned char* RES_star
)
{
	unsigned char outbuf[32];
	Universal_key_generator(0x6B, CKIK, SNname, RAND, RES, outbuf);
	memcpy(RES_star, outbuf + 16, 16);
	return 1;
}

//33.501 A.5
int HRES_star_generator(
	const unsigned char* RAND,
	const unsigned char* RES_star,
	unsigned char* HRES_star
)
{
	unsigned char S[MAX_LEN] = { 0 };
	unsigned short L1 = strlen((const char*)RAND);
	memcpy(S, RAND, L1);
	unsigned short L2 = strlen((const char*)RES_star);
	memcpy(S + L1, RES_star, L2);
	unsigned char outbuf[32] = { 0 };
	SHA256(S, L1 + L2, outbuf);
	memcpy(HRES_star, outbuf + 16, 16);
	return 1;
}

//33.501 A.6
int Kseaf_generator(
	const unsigned char* Kausf,
	const unsigned char* SNname,
	unsigned char* Kseaf
)
{
	Universal_key_generator(0x6C, Kausf, SNname, NULL, NULL, Kseaf);
	return 1;
}

//33.501 A.7
int Kamf_generator(
	const unsigned char* Kseaf,
	const unsigned char* SUPI,
	const unsigned char* ABBA,
	unsigned char* Kamf
)
{
	Universal_key_generator(0x6D, Kseaf, SUPI, ABBA, NULL, Kamf);
	return 1;
}

//33.501 A.8
int algorithm_key_generator(
	const unsigned char* key,
	const unsigned char algorithm_type_distinguisher,
	const unsigned char algorithm_identity,
	unsigned char* alg_key
)
{
	unsigned char outbuf[MAX_LEN] = { 0 };
	Universal_key_generator(0x69, key, &algorithm_type_distinguisher, &algorithm_identity, NULL, outbuf);
	memcpy(alg_key, outbuf + 16, 16);
	return 1;
}

//33.501 A.9
int KgNB_generator(
	const unsigned char* Kamf,
	const unsigned char* Uplink_NAS_COUNT,
	const unsigned char access_type_distinguisher,
	unsigned char* KgNB
)
{
	Universal_key_generator(0x6E, Kamf, Uplink_NAS_COUNT, &access_type_distinguisher, NULL, KgNB);
	return 1;
}

//33.501 A.10
int NH_generator(
	const unsigned char* Kamf,
	const unsigned char* SYNC_input,
	unsigned char* NH
)
{
	Universal_key_generator(0x6F, Kamf, SYNC_input, NULL, NULL, NH);
	return 1;
}

//33.501 A.11
int Kng_RAN_new_gNB_generator(
	const unsigned char* key,
	const unsigned char* PCI,
	const unsigned char* ARFCN_DL,
	unsigned char* Kng_RAN
)
{
	Universal_key_generator(0x70,key,PCI,ARFCN_DL,NULL,Kng_RAN);
	return 1;
}

//33.501 A.12
int Kng_RAN_new_ng_eNB_generator(
	const unsigned char* key,
	const unsigned char* PCI,
	const unsigned char* EARFCN_DL,
	unsigned char* Kng_RAN
)
{
	Universal_key_generator(0x71, key, PCI, EARFCN_DL, NULL, Kng_RAN);
	return 1;
}

//33.501 A.13
int Kamf_new_generator(
	const unsigned char* Kamf,
	const unsigned char* DIRECTION,
	const unsigned char* COUNT,
	unsigned char* Kamf_new
)
{
	Universal_key_generator(0x72, Kamf, DIRECTION, COUNT, NULL, Kamf_new);
	return 1;
}

//33.501 A.14
int Kasme_new_generator(
	const unsigned char FC,  //FC = 0x73 for uplink, FC = 0x74 for downlink
	const unsigned char* Kamf,
	const unsigned char* NAS_link_COUNT,
	unsigned char* Kasme_new
)
{
	Universal_key_generator(FC, Kamf, NAS_link_COUNT, NULL, NULL, Kasme_new);
	return 1;
}

//33.501 A.15
int Kamf_new_from_ASME_generator(
	const unsigned char FC,  //FC = 0x75 for uplink, FC = 0x76 for downlink
	const unsigned char* Kasme,
	const unsigned char* NAS_link_COUNT,
	unsigned char* Kamf_new
)
{
	Universal_key_generator(FC, Kasme, NAS_link_COUNT, NULL, NULL, Kamf_new);
	return 1;
}

//33.501 A.16
int Ksn_generator(
	const unsigned char* key,
	const unsigned char* SN_counter,
	unsigned char* Ksn
)
{
	Universal_key_generator(0x79, key, SN_counter, NULL, NULL, Ksn);
	return 1;
}

//33.501 A.17
int SoR_MAC_I_ausf_generator(
	const unsigned char* Kausf,
	const unsigned char* SoR_header,
	const unsigned char* Counter_sor,
	const unsigned char* PLMN_ID,
	unsigned char* SoR_MAC_I_ausf
)
{
	unsigned char outbuf[32];
	Universal_key_generator(0x77, Kausf, SoR_header, Counter_sor, PLMN_ID, outbuf);
	memcpy(SoR_MAC_I_ausf, outbuf + 16, 16);
	return 1;
}

//33.501 A.18
int SoR_MAC_I_UE_generator(
	const unsigned char* Kausf,
	const unsigned char* SoR_Acknowledgement,
	const unsigned char* Counter_sor,
	unsigned char* SoR_MAC_I_UE
)
{
	unsigned char outbuf[32];
	Universal_key_generator(0x78, Kausf, SoR_Acknowledgement, Counter_sor, NULL, outbuf);
	memcpy(SoR_MAC_I_UE, outbuf + 16, 16);
	return 1;
}

//33.501 A.19
int UPU_MAC_I_ausf_generator(
	const unsigned char* Kausf,
	const unsigned char*  UE_Parameters_Update_Data,
	const unsigned char* Counter_upu,
	unsigned char* UPU_MAC_I_ausf
)
{
	unsigned char outbuf[32];
	Universal_key_generator(0x7B, Kausf, UE_Parameters_Update_Data, Counter_upu, NULL, outbuf);
	memcpy(UPU_MAC_I_ausf, outbuf + 16, 16);
	return 1;
}

//33.501 A.20
int UPU_MAC_I_UE_generator(
	const unsigned char* Kausf,
	const unsigned char*  UPU_Acknowledgement,
	const unsigned char* Counter_upu,
	unsigned char* UPU_MAC_I_UE
)
{
	unsigned char outbuf[32];
	Universal_key_generator(0x7C, Kausf, UPU_Acknowledgement, Counter_upu, NULL, outbuf);
	memcpy(UPU_MAC_I_UE, outbuf + 16, 16);
	return 1;
}

//33.501 A.21
int Kasme_srvcc_generator(
	const unsigned char* Kamf,
	const unsigned char*  NAS_Downlink_COUNT,
	unsigned char* Kasme_srvcc
)
{
	unsigned char outbuf[32];
	Universal_key_generator(0x7D, Kamf, NAS_Downlink_COUNT, NULL, NULL, Kasme_srvcc);
	return 1;
}

/*
int Kausf_5G_AKA_generator(
	const unsigned char* CK,
	const unsigned char* IK,
	const unsigned char* SQN_xor_AK,
	const unsigned char* SNname,
	unsigned char* Kausf
)
{
	unsigned char KEY[32] = { 0 };
	memcpy(KEY, CK, 16);
	memcpy(KEY+16, IK, 16);

	unsigned char S[MAX_LEN] = { 0 };
	S[0] = 0x6A;
	unsigned short L0 = strlen((const char*)SNname);
	memcpy(S + 1, SNname, L0);
	S[1 + L0] = L0 >> 8;
	S[1 + L0 + 1] = L0 & 0xFF;
	unsigned short L1 = strlen((const char*)SQN_xor_AK);
	memcpy(S + 1 + L0 + 2, SQN_xor_AK, L1);
	S[1 + L0 + 2 + L1] = L1 >> 8;
	S[1 + L0 + 2 + L1 + 1] = L1 & 0xFF;

	HMAC_SHA_256(KEY, S, L0 + L1 + 5, Kausf, 32);
	return 1;
}

int CKIK_new_generator(
	const unsigned char* CK,
	const unsigned char* IK,
	const unsigned char* SQN_xor_AK,
	const unsigned char* SNname,
	unsigned char* CK_new,
	unsigned char* IK_new
)
{
	unsigned char KEY[32] = { 0 };
	memcpy(KEY, CK, 16);
	memcpy(KEY + 16, IK, 16);

	unsigned char S[MAX_LEN] = { 0 };
	S[0] = 0x20;
	unsigned short L0 = strlen((const char*)SNname);
	memcpy(S + 1, SNname, L0);
	S[1 + L0] = L0 >> 8;
	S[1 + L0 + 1] = L0 & 0xff;
	unsigned short L1 = strlen((const char*)SQN_xor_AK);
	memcpy(S + 1 + L0 + 2, SQN_xor_AK, L1);
	S[1 + L0 + 2 + L1] = L1 >> 8;
	S[1 + L0 + 2 + L1 + 1] = L1 & 0xFF;

	unsigned char outbuf[32] = { 0 };
	HMAC_SHA_256(KEY, S, L0 + L1 + 5, outbuf, 32);
	memcpy(CK_new, outbuf, 16);
	memcpy(IK_new, outbuf + 16, 16);
}

int RES_star_generator(
	const unsigned char* CK,
	const unsigned char* IK,
	const unsigned char* RES,
	const unsigned char* RAND,
	const unsigned char* SNname,
	unsigned char* RES_star
)
{
	unsigned char KEY[32] = { 0 };
	memcpy(KEY, CK, 16);
	memcpy(KEY + 16, IK, 16);

	unsigned char S[MAX_LEN] = { 0 };
	S[0] = 0x6B;
	unsigned short L0 = strlen((const char*)SNname);
	memcpy(S + 1, SNname, L0);
	S[1 + L0] = L0 >> 8;
	S[1 + L0 + 1] = L0 & 0xFF;
	unsigned short L1 = strlen((const char*)RAND);
	memcpy(S + 1 + L0 + 2, RAND, L1);
	S[1 + L0 + 2 + L1] = L1 >> 8;
	S[1 + L0 + 2 + L1 + 1] = L1 & 0xFF;
	unsigned short L2 = strlen((const char*)RES);
	memcpy(S + 1 + L0 + 2 + L1 + 2, RES, L2);
	S[1 + L0 + 2 + L1 + 2 + L2] = L2 >> 8;
	S[1 + L0 + 2 + L1 + 2 + L2 + 1] = L2 & 0xFF;

	unsigned char outbuf[32] = { 0 };
	HMAC_SHA_256(KEY, S, L0 + L1 + L2 + 7, outbuf, 32);
	memcpy(RES_star, outbuf + 16, 16);
	return 1;
}

int Kseaf_generator(
	const unsigned char* Kausf,
	const unsigned char* SNname,
	unsigned char* Kseaf
)
{
	unsigned char S[MAX_LEN] = { 0 };
	S[0] = 0x6C;
	unsigned short L0 = strlen((const char*)SNname);
	memcpy(S + 1, SNname, L0);
	S[1 + L0] = L0 >> 8;
	S[1 + L0 + 1] = L0 & 0xFF;

	HMAC_SHA_256(Kausf, S, L0 + 3, Kseaf, 32);
	return 1;
}

int Kamf_generator(
	const unsigned char* Kseaf,
	const unsigned char* SUPI,
	const unsigned char* ABBA,
	unsigned char* Kamf
)
{
	unsigned char S[MAX_LEN] = { 0 };
	S[0] = 0x6D;
	unsigned short L0 = strlen((const char*)SUPI);
	memcpy(S + 1, SUPI, L0);
	S[1 + L0] = L0 >> 8;
	S[1 + L0 + 1] = L0 & 0xFF;
	unsigned short L1 = strlen((const char*)ABBA);
	memcpy(S + 1 + L0 + 2, ABBA, L1);
	S[1 + L0 + 2 + L1] = L1 >> 8;
	S[1 + L0 + 2 + L1 + 1] = L1 & 0xFF;

	HMAC_SHA_256(Kseaf, S, L0 + L1 + 5, Kamf, 32);
	return 1;
}

int algorithm_key_generator(
	const unsigned char* key,
	const unsigned char algorithm_type_distinguisher,
	const unsigned char algorithm_identity,
	unsigned char* alg_key
)
{
	unsigned char S[MAX_LEN] = { 0 };
	S[0] = 0x69;
	unsigned short L0 = strlen((const char*)algorithm_type_distinguisher);
	memcpy(S + 1, &algorithm_type_distinguisher, L0);
	S[1 + L0] = L0 >> 8;
	S[1 + L0 + 1] = L0 & 0xFF;
	unsigned short L1 = strlen((const char*)algorithm_identity);
	memcpy(S + 1 + L0 + 2, &algorithm_identity, L1);
	S[1 + L0 + 2 + L1] = L1 >> 8;
	S[1 + L0 + 2 + L1 + 1] = L1 & 0xFF;

	HMAC_SHA_256(key, S, L0 + L1 + 5, alg_key, 32);
	return 1;
}

int KgNB_generator(
	const unsigned char* Kamf,
	const unsigned char* Uplink_NAS_COUNT,
	const unsigned char access_type_distinguisher,
	unsigned char* KgNB
)
{
	unsigned char S[MAX_LEN] = { 0 };
	S[0] = 0x6E;
	unsigned short L0 = strlen((const char*)Uplink_NAS_COUNT);
	memcpy(S + 1, Uplink_NAS_COUNT, L0);
	S[1 + L0] = L0 >> 8;
	S[1 + L0 + 1] = L0 & 0xFF;
	unsigned short L1 = strlen((const char*)access_type_distinguisher);
	memcpy(S + 1 + L0 + 2, &access_type_distinguisher, L1);
	S[1 + L0 + 2 + L1] = L1 >> 8;
	S[1 + L0 + 2 + L1 + 1] = L1 & 0xFF;

	HMAC_SHA_256(Kamf, S, L0 + L1 + 5, KgNB, 32);
	return 1;
}

int NH_generator(
	const unsigned char* Kamf,
	const unsigned char* SYNC_input,
	unsigned char* NH
)
{
	unsigned char S[MAX_LEN] = { 0 };
	S[0] = 0x6F;
	unsigned short L0 = strlen((const char*)SYNC_input);
	memcpy(S + 1, SYNC_input, L0);
	S[1 + L0] = L0 >> 8;
	S[1 + L0 + 1] = L0 & 0xFF;

	HMAC_SHA_256(Kamf, S, L0 + 3, NH, 32);
	return 1;
}
*/