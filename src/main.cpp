#include <iostream>
#include <fstream>
#include <cstring>
#include <string>
#include <random>
#include "Blowfish.h"
#include <iomanip>
using namespace std;


bool testEncrypt();
bool testDecrypt();


static uint64_t fromBytes(unsigned char const* bytes)
{
	return (uint64_t)bytes[0] << 56 | (uint64_t)bytes[1] << 48 | (uint64_t)bytes[2] << 40 | (uint64_t)bytes[3] << 32 | (uint64_t)bytes[4] << 24 | (uint64_t)bytes[5] << 16 | (uint64_t)bytes[6] << 8 | (uint64_t)bytes[7];
}

static void toBytes(uint64_t num, unsigned char* bytes)
{
	for (int i = 7; i >= 0; i--)
	{
		bytes[i] = num & 0xff;
		num >>= 8;
	}
}


int main()
{
	return !testEncrypt() || !testDecrypt();
}

bool testEncrypt()
{
	ifstream f("../test.txt");

	unsigned char key[8];
	unsigned char input[8];
	f >> setbase(16);

	while (!f.eof())
	{
		uint64_t temp;

		f >> temp;
		toBytes(temp, key);

		f >> temp;
		toBytes(temp, input);

		f >> temp;

		Blowfish fish(key, 64);
		fish.encrypt(input, 8);

		toBytes(temp, key);

		if (memcmp(input, key, 8))
			return false;
		
	}
	return true;
}

bool testDecrypt()
{
	ifstream f("../test.txt");

	unsigned char key[8];
	unsigned char input[8];
	unsigned char expected[8];
	f >> setbase(16);

	while (!f.eof())
	{
		uint64_t temp;

		f >> temp;
		toBytes(temp, key);

		f >> temp;
		toBytes(temp, expected);

		f >> temp;
		toBytes(temp, input);

		Blowfish fish(key, 64);
		fish.decrypt(input, 8);

		if (memcmp(input, expected, 8))
			return false;
		
	}
	return false;
}