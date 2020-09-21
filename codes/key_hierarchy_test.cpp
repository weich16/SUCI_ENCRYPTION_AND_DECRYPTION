// key_hierarchy_test.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include "key_hierarchy_lib.h"

using namespace std;

int main()
{
	//test data sample
	unsigned char CKIK[] =
	{ 0x5a,0x8d,0x38,0x86,0x48,0x20,0x19,0x7c,0x33,0x94,0xb9,0x26,0x13,0xb2,0x0b,0x91,
	  0x63,0x3c,0xbd,0x89,0x71,0x19,0x27,0x3b,0xf8,0xe4,0xa6,0xf4,0xee,0xc0,0xa6,0x50 };
	unsigned char SNname[] = "networkSecurity.tsinghua.edu.cn";
	unsigned char SQN_xor_AK[] = { 0x5a,0x8d,0x38,0x86,0x48,0x20 };
	unsigned char Identity[] = "student";
	unsigned char RAND[] =
	{ 0x72,0xDA,0x71,0x97,0x62,0x34,0xCE,0x83,0x3A,0x69,0x07,0x42,0x58,0x67,0xB8,0x2E,
	  0x07,0x4D,0x44,0xEF,0x90,0x7D,0xFB,0x4B,0x3E,0x21,0xC1,0xC2,0x25,0x6E,0xBC,0xD1 };
	unsigned char RES[] = //or XRES
	{ 0xF1,0xAB,0x10,0x74,0x47,0x7E,0xBC,0xC7,0xF5,0x54,0xEA,0x1C,0x5F,0xC3,0x68,0xB1,
	  0x61,0x67,0x30,0x15,0x5E,0x00,0x41,0xAC,0x44,0x7D,0x63,0x01,0x97,0x5F,0xEC,0xDA };
	unsigned char SUPI[] = "234150999999999";
	unsigned char ABBA[] = { 0x00,0x00 };
	unsigned char alg_type = 0x01; //i.e. N-NAS-enc_alg;
	unsigned char alg_identity = 0x01;
	unsigned char Uplink_NAS_COUNT[] = { 0xb2,0xe9,0x2f,0x83 };
	unsigned char access_type = 0x01; // i.e. 3GPP access
	unsigned char SYNC_input[] =
	{ 0x9A,0xAB,0x83,0x76,0x59,0x70,0x21,0xE8,0x55,0x67,
	  0x39,0x6E,0x68,0xC6,0x6D,0xF3,0x2C,0x0F,0x41,0xE9 };
	unsigned char PCI[] = { 0x00,0x01 };
	unsigned char ARFCN_DL[] = { 0x00,0x00,0x01 };
	unsigned char EARFCN_DL[] = { 0x00,0x00,0x02 };
	unsigned char DIRECTION = 0x01;
	unsigned char COUNT[] = { 0xcb,0x02,0x35,0x24 };
	unsigned char NAS_link_COUNT[] = { 0x46,0xA3,0x3F,0xC2 };
	unsigned char SN_counter[] = { 0x00, 0x10 };
	unsigned char SoR_header[] = { 0xcd,0xdd,0x9e,0x73,0x0e,0xf3,0xfa,0x87 };
	unsigned char Counter_sor[] = { 0x00, 0x3f };
	unsigned char PLMN_ID[] = "46000";
	unsigned char UE_Parameters_Update_Data[] = "This is an update data.";
	unsigned char Counter_upu[] = { 0xab,0xcd };

	//33.501 A.2
	cout << "================================================";
	cout << "Test for 33.501 A.2\n\n";
	unsigned char Kausf[32];
	Kausf_5G_AKA_generator(CKIK, SNname, SQN_xor_AK, Kausf);
	cout << "Kausf:";
	display(Kausf, 32);

	//33.501 A.3
	cout << "================================================";
	cout << "Test for 33.501 A.3\n\n";
	unsigned char CK_new[16];
	unsigned char IK_new[16];
	CKIK_new_generator(CKIK, SNname, SQN_xor_AK, CK_new, IK_new);
	cout << "CK_new:";
	display(CK_new, 16);
	cout << "IK_new:";
	display(IK_new, 16);

	//rfc 5448 MK
	cout << "================================================";
	cout << "Test for rfc 5448 MK\n\n";
	unsigned char MK[224];
	MK_EAP_AKA_new_generator(CK_new, IK_new, Identity, MK);
	cout << "MK:";
	display(MK, 208);

	//rfc 5448 key set
	cout << "================================================";
	cout << "Test for rfc 5448 key set\n\n";
	unsigned char K_encr[16];
	unsigned char K_aut[32];
	unsigned char K_re[32];
	unsigned char MSK[64];
	unsigned char EMSK[64];
	//unsigned char Kausf
	Kset_EAP_AKA_new_generator(MK, K_encr, K_aut, K_re, MSK, EMSK, Kausf);
	cout << "K_encr:";
	display(K_encr, 16);
	cout << "K_aut:";
	display(K_aut, 32);
	cout << "K_re:";
	display(K_re, 32);
	cout << "MSK:";
	display(MSK, 64);
	cout << "EMSK:";
	display(EMSK, 64);

	//33.501 A.4
	cout << "================================================";
	cout << "Test for 33.501 A.4\n\n";
	unsigned char RES_star[16]; //or XRES_star
	RES_star_generator(CKIK, SNname, RAND, RES, RES_star);
	cout << "RES_star:";
	display(RES_star, 16);

	//33.501 A.5
	cout << "================================================";
	cout << "Test for 33.501 A.5\n\n";
	unsigned char HRES_star[16]; //or HXRES_star
	HRES_star_generator(RAND, RES_star, HRES_star);
	cout << "HRES_star:";
	display(HRES_star, 16);

	//33.501 A.6
	cout << "================================================";
	cout << "Test for 33.501 A.6\n\n";
	unsigned char Kseaf[32]; //or HXRES_star
	Kseaf_generator(Kausf, SNname, Kseaf);
	cout << "Kseaf:";
	display(Kseaf, 32);

	//33.501 A.7
	cout << "================================================";
	cout << "Test for 33.501 A.7\n\n";
	unsigned char Kamf[32];
	Kamf_generator(Kseaf, SUPI, ABBA, Kamf);
	cout << "Kamf:";
	display(Kamf, 32);

	//33.501 A.8
	cout << "================================================";
	cout << "Test for 33.501 A.8\n\n";
	unsigned char Kalg[16];
	algorithm_key_generator(Kamf, alg_type, alg_identity, Kalg); // Kamf or KgNB/Ksn
	cout << "Kalg:";
	display(Kalg, 16);

	//33.501 A.9
	cout << "================================================";
	cout << "Test for 33.501 A.9\n\n";
	unsigned char KgNB[32]; //or Kn3iwf
	KgNB_generator(Kamf, Uplink_NAS_COUNT, access_type, KgNB);
	cout << "KgNB:";
	display(KgNB, 32);

	//33.501 A.10
	cout << "================================================";
	cout << "Test for 33.501 A.10\n\n";
	unsigned char NH[32];
	NH_generator(Kamf, SYNC_input, NH);
	cout << "NH:";
	display(NH, 32);

	//33.501 A.11
	cout << "================================================";
	cout << "Test for 33.501 A.11\n\n";
	unsigned char Kng_RAN[32];
	Kng_RAN_new_gNB_generator(NH, PCI, ARFCN_DL, Kng_RAN);
	cout << "Kng_RAN_gNB:";
	display(Kng_RAN, 32);

	//33.501 A.12
	cout << "================================================";
	cout << "Test for 33.501 A.12\n\n";
	Kng_RAN_new_ng_eNB_generator(NH, PCI, EARFCN_DL, Kng_RAN);
	cout << "Kng_RAN_ng_eNB:";
	display(Kng_RAN, 32);

	//33.501 A.13
	cout << "================================================";
	cout << "Test for 33.501 A.13\n\n";
	unsigned char Kamf_new[32];
	Kamf_new_generator(Kamf, DIRECTION, COUNT, Kamf_new);
	cout << "Kamf_new:";
	display(Kamf_new, 32);

	//33.501 A.14
	cout << "================================================";
	cout << "Test for 33.501 A.14\n\n";
	unsigned char Kasme_new[32];
	Kasme_new_generator(0x73, Kamf, NAS_link_COUNT, Kasme_new);
	cout << "Kasme_new:";
	display(Kasme_new, 32);

	//33.501 A.15
	cout << "================================================";
	cout << "Test for 33.501 A.15\n\n";
	Kamf_new_from_ASME_generator(0x75, Kasme_new, NAS_link_COUNT, Kamf_new);
	cout << "Kamf_new_from_AMSE:";
	display(Kamf_new, 32);

	//33.501 A.16
	cout << "================================================";
	cout << "Test for 33.501 A.16\n\n";
	unsigned char Ksn[32];
	Ksn_generator(Kng_RAN, SN_counter, Ksn);
	cout << "Ksn:";
	display(Ksn, 32);

	//33.501 A.17
	cout << "================================================";
	cout << "Test for 33.501 A.17\n\n";
	unsigned char SoR_MAC_I_ausf[16];
	SoR_MAC_I_ausf_generator(Kausf, SoR_header, Counter_sor, PLMN_ID, SoR_MAC_I_ausf);
	cout << "SoR_MAC_I_ausf:";
	display(SoR_MAC_I_ausf, 16);

	//33.501 A.18
	cout << "================================================";
	cout << "Test for 33.501 A.18\n\n";
	unsigned char SoR_MAC_I_UE[16];
	SoR_MAC_I_UE_generator(Kausf, 0x01, Counter_sor, SoR_MAC_I_UE);
	cout << "SoR_MAC_I_UE:";
	display(SoR_MAC_I_UE, 16);

	//33.501 A.19
	cout << "================================================";
	cout << "Test for 33.501 A.19\n\n";
	unsigned char UPU_MAC_I_ausf[16];
	UPU_MAC_I_ausf_generator(Kausf, UE_Parameters_Update_Data, Counter_upu, UPU_MAC_I_ausf);
	cout << "UPU_MAC_I_ausf:";
	display(UPU_MAC_I_ausf, 16);

	//33.501 A.20
	cout << "================================================";
	cout << "Test for 33.501 A.20\n\n";
	unsigned char UPU_MAC_I_UE[16];
	UPU_MAC_I_UE_generator(Kausf, 0x01, Counter_upu, UPU_MAC_I_UE);
	cout << "UPU_MAC_I_UE:";
	display(UPU_MAC_I_UE, 16);

	//33.501 A.21
	cout << "================================================";
	cout << "Test for 33.501 A.21\n\n";
	unsigned char  Kamse_srvcc[32];
	Kasme_srvcc_generator(Kamf, NAS_link_COUNT, Kamse_srvcc);
	cout << "Kamse_srvcc:";
	display(Kamse_srvcc, 32);
}

