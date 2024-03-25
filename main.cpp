#include <iostream>
#include <fstream>
#include <cstring>
#include <string>
#include <random>
#include "Blowfish.h"

using namespace std;

int main()
{
	ifstream f("key", ios::binary);
	char key[56];
	f.read(key, 56);

	Blowfish fish(key);
	char input[8];
	strcpy(input, "1234567");
	fish.encrypt(input, 8);
	fish.decrypt(input, 8);
	cout << input;
}

