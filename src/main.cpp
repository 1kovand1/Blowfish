#include <iostream>
#include <fstream>
#include <cstring>
#include <string>
#include <random>
#include "Blowfish.h"
#include <iomanip>
#include <print>
using namespace std;


void testDecrypt();
void testEncrypt();
void testHash();

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
	testHash();
}

void testDecrypt()
{
	ifstream f("../test1.txt");

	unsigned char key[8];
	unsigned char input[8];
	f >> setbase(16);
	cout << setbase(16) << left << uppercase;

	cout << '|' << setw(16) << setfill('-') << "-" << '-' << setw(16) << setfill('-') << "-" << '-' << setw(16) << setfill('-') << "-" << '-' << setw(16) << setfill('-') << "-" << "|\n";
	cout << setfill(' ') << '|' << setw(16) << "key" << '|' << setw(16) << "cipher" << '|' << setw(16) << "expected open" << '|' << setw(16) << "result" << "|\n";

	while (!f.eof())
	{
		cout << '|' << setw(16) << setfill('-') << "-" << '|' << setw(16) << setfill('-') << "-" << '|' << setw(16) << setfill('-') << "-" << '|' << setw(16) << setfill('-') << "-" << "|\n";
		cout << setfill('0');
		cout << '|';
		uint64_t temp;

		f >> temp;
		cout << setw(16) << temp << '|';
		toBytes(temp, key);

		f >> temp;
		cout << setw(16) << temp << '|';
		toBytes(temp, input);

		f >> temp;
		cout << setw(16) << temp << '|';

		Blowfish fish(key, 64);
		fish.decrypt(input, 8);
		cout << setw(16) << fromBytes(input) << "|\n";


	}
	cout << '|' << setw(16) << setfill('-') << "-" << '-' << setw(16) << setfill('-') << "-" << '-' << setw(16) << setfill('-') << "-" << '-' << setw(16) << setfill('-') << "-" << "|\n";
}

void testEncrypt()
{
	ifstream f("../test.txt");

	unsigned char key[8];
	unsigned char input[8];
	f >> setbase(16);
	cout << setbase(16) << left << uppercase;

	cout << '|' << setw(16) << setfill('-') << "-" << '-' << setw(16) << setfill('-') << "-" << '-' << setw(16) << setfill('-') << "-" << '-' << setw(16) << setfill('-') << "-" << "|\n";
	cout << setfill(' ') << '|' << setw(16) << "key" << '|' << setw(16) << "open text" << '|' << setw(16) << "expected cipher" << '|' << setw(16) << "result" << "|\n";


	while (!f.eof())
	{
		cout << '|' << setw(16) << setfill('-') << "-" << '+' << setw(16) << setfill('-') << "-" << '+' << setw(16) << setfill('-') << "-" << '+' << setw(16) << setfill('-') << "-" << "|\n";
		cout << setfill('0');
		cout << '|';
		uint64_t temp;

		f >> temp;
		cout << setw(16) << temp << '|';
		toBytes(temp, key);

		f >> temp;
		cout << setw(16) << temp << '|';
		toBytes(temp, input);

		f >> temp;
		cout << setw(16) << temp << '|';

		Blowfish fish(key, 64);
		fish.encrypt(input, 8);
		cout << setw(16) << fromBytes(input) << "|\n";
		
	}
	cout << '|' << setw(16) << setfill('-') << "-" << '-' << setw(16) << setfill('-') << "-" << '-' << setw(16) << setfill('-') << "-" << '-' << setw(16) << setfill('-') << "-" << "|\n";
}

void testHash()
{
	ifstream file("../test2.txt");
	std::string str;
	while (file.peek() != EOF)
	{
		getline(file, str);
		for (unsigned char c : str)
			print("{:08b}", c);
		cout << "->" << setbase(16) << uppercase << setw(16) << setfill('0') << Blowfish::hash((const uint8_t*)str.c_str(), str.size()) << '\n';
	}
}

