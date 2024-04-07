#include <iostream>
#include <fstream>
#include <cstring>
#include <string>
#include <random>
#include "Blowfish.h"

using namespace std;

int main()
{
	//ifstream f("key", ios::binary);
	unsigned char key[8];
	unsigned char input[8];
	//f.read(key, 56);
	for (int i = 0; i < 8; i++)
		scanf_s("%2hhx", key + i);
	for (int i = 0; i < 8; i++)
		scanf_s("%2hhx", input + i);

	Blowfish fish(key, 8);
	
	//strcpy(input, "1234567");
	fish.encrypt(input, 8);
	//fish.decrypt(input, 8);
	//cout << input;
	for (int i = 0; i < 8; i++)
	{
		printf_s("%hhx", input[i]);
	}
}

