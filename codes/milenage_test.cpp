#include "milenage.h";
#include <iostream>

using namespace std;

void display(const unsigned char* buf, int buflen)
{
	for (int i = 0; i < buflen; i++) printf("%02x", buf[i]);
	printf("\n\n");
}

int str2byte(const unsigned char* str, unsigned char* byte_stream, int datalen)
{
	int tmp = 0;
	for (int i = 0; i < datalen * 2; i += 2)
	{
		tmp = 0;
		if (48 <= str[i] && str[i] <= 57) tmp += 16 * (int(str[i]) - 48);
		if (65 <= str[i] && str[i] <= 70) tmp += 16 * (int(str[i]) - 55);
		if (97 <= str[i] && str[i] <= 102) tmp += 16 * (int(str[i]) - 87);
		if (48 <= str[i + 1] && str[i + 1] <= 57) tmp += int(str[i + 1]) - 48;
		if (65 <= str[i + 1] && str[i + 1] <= 70) tmp += int(str[i + 1]) - 55;
		if (97 <= str[i + 1] && str[i + 1] <= 102) tmp += int(str[i + 1]) - 87;
		byte_stream[i / 2] = char(tmp);
		//printf("%02x", byte_stream[i/2]);
	}
	return 1;
}

int dataReader(unsigned char* outBuf)
{
	char strBuf[1024] = { 0 };
	cin.getline(strBuf, 1024);
	int datalen = (int)strlen((char*)strBuf) / 2;
	if (!str2byte((unsigned char*)strBuf, outBuf, datalen)) return 0;
	return datalen;
}

int main()
{
	/*
	//Rijndael test
	unsigned char key[16];
	unsigned char plaintext[16];
	unsigned char ciphertext[16];

	dataReader(key);
	dataReader(plaintext);

	RijndaelKeySchedule(key);
	RijndaelEncrypt(plaintext, ciphertext);
	
	display(ciphertext, 16);
	*/

	//milenage test
	unsigned char K[16];
	unsigned char RAND[16];
	unsigned char SQN[6];
	unsigned char AMF[2];
	//unsigned char OP[16];
	unsigned char MAC_A[8];
	unsigned char MAC_S[8];
	unsigned char RES[8];
	unsigned char CK[16];
	unsigned char IK[16];
	unsigned char AK[6];

	dataReader(K);
	dataReader(RAND);
	dataReader(SQN);
	dataReader(AMF);
	dataReader(OP);

	f1(K, RAND, SQN, AMF, MAC_A);
	display(MAC_A, 8);
	f1star(K, RAND, SQN, AMF, MAC_S);
	display(MAC_S, 8);
	f2345(K, RAND, RES, CK, IK, AK);
	display(RES,8);
	display(CK, 16);
	display(IK, 16);
	display(AK, 6);
	f5star(K, RAND, AK);
	display(AK, 6);
}
