#include "Blowfish.h"
#include <algorithm>
#include <cassert>

uint32_t Blowfish::F(uint32_t in)
{
	/*uint32_t h = sBox[0][in >> 24] + sBox[1][in >> 16 & 0xff];
	return (h ^ sBox[2][in >> 8 & 0xff]) + sBox[3][in & 0xff];*/
	word w;
	w.num = in;
	return ((sBox[0][w.bytes.zero] + sBox[1][w.bytes.first]) ^ sBox[2][w.bytes.second]) + sBox[3][w.bytes.third];
}

void Blowfish::encryptBlock(uint32_t& left, uint32_t& right)
{
	for (int i = 0; i < 15; ++i)
	{
		left ^= p[i];
		right ^= F(left);
		std::swap(left, right);
	}
	left ^= p[15];
	right ^= F(left);

	left ^= p[17];
	right ^= p[16];
}

void Blowfish::decryptBlock(uint32_t& left, uint32_t& right)
{
	for (int i = 17; i > 2; --i)
	{
		left ^= p[i];
		right ^= F(left);
		std::swap(left, right);
	}
	left ^= p[2];
	right ^= F(left);
	left ^= p[0];
	right ^= p[1];
}

Blowfish::Blowfish(unsigned char const* key, size_t keyLen)
{
	for (int i = 0; i < 18; ++i)
	{
		word w;
		w.bytes.zero = key[(4 * i) % keyLen];
		w.bytes.first = key[(4 * i + 1) % keyLen];
		w.bytes.second = key[(4 * i + 2) % keyLen];
		w.bytes.third = key[(4 * i + 3) % keyLen];
		p[i] ^= w.num;
	}
	uint32_t l = 0, r = 0;
	for (int i = 0; i < 18; ++i)
	{
		encryptBlock(l, r);
		p[i] = l;
		p[++i] = r;
	}
	for (int i = 0; i < 4; ++i)
		for (int j = 0; j < 256; ++j)
		{
			encryptBlock(l, r);
			sBox[i][j] = l;
			sBox[i][++j] = r;
		}
}

void Blowfish::encrypt(unsigned char* data, size_t dataLen)
{
	#ifdef _MSC_VER
	assert(dataLen % 8 == 0, "Data length must be a multiple of 8 bytes");
	#else
	assert(dataLen % 8 == 0);
	#endif
	size_t blocksCount = dataLen / 8;
	//uint32_t* blocks = reinterpret_cast<uint32_t*>(data);
	for (size_t i = 0; i < blocksCount; i++)
	{
		word w1, w2;
		w1.bytes.zero = data[8*i];
		w1.bytes.first = data[8 * i + 1];
		w1.bytes.second = data[8 * i + 2];
		w1.bytes.third = data[8 * i + 3];
		w2.bytes.zero = data[8 * i + 4];
		w2.bytes.first = data[8 * i + 5];
		w2.bytes.second = data[8 * i + 6];
		w2.bytes.third = data[8 * i + 7];
		encryptBlock(w1.num, w2.num);
		data[8 * i] = w1.bytes.zero;
		data[8 * i + 1] = w1.bytes.first;
		data[8 * i + 2] = w1.bytes.second;
		data[8 * i + 3] = w1.bytes.third;
		data[8 * i + 4] = w2.bytes.zero;
		data[8 * i + 5] = w2.bytes.first;
		data[8 * i + 6] = w2.bytes.second;
		data[8 * i + 7] = w2.bytes.third;

	}
}

void Blowfish::decrypt(unsigned char* data, size_t dataLen)
{
	#ifdef _MSC_VER
	assert(dataLen % 8 == 0, "Data length must be a multiple of 8 bytes");
	#else
	assert(dataLen % 8 == 0);
	#endif
	size_t blocksCount = dataLen / 8;
	uint32_t* blocks = reinterpret_cast<uint32_t*>(data);
	for (size_t i = 0; i < blocksCount; i++)
		decryptBlock(blocks[2 * i], blocks[2 * i + 1]);
}


