#include "Blowfish.h"
#include <algorithm>
#include <cassert>

uint32_t Blowfish::F(uint32_t in)
{
	char const* bytes = reinterpret_cast<char const*>(&in);
	return (sBox[0][bytes[0]] + sBox[1][bytes[1]] ^ sBox[2][bytes[2]]) + sBox[3][bytes[3]];
}

void Blowfish::encryptBlock(uint32_t& left, uint32_t& right)
{
	for (int i = 0; i < 16; ++i)
	{
		left ^= p[i];
		right ^= F(left);
		std::swap(left, right);
	}
	std::swap(left, right);
	left ^= p[17];
	right ^= p[16];
}

void Blowfish::decryptBlock(uint32_t& left, uint32_t& right)
{
	for (int i = 17; i > 1; --i)
	{
		left ^= p[i];
		right ^= F(left);
		std::swap(left, right);
	}
	std::swap(left, right);
	left ^= p[0];
	right ^= p[1];
}

Blowfish::Blowfish(char const* key, size_t keyLen)
{
	uint32_t const* dwords = reinterpret_cast<uint32_t const*>(key);
	for (int i = 0; i < 18; ++i)
		p[i] ^= dwords[i % (keyLen / 32)];
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

void Blowfish::encrypt(char* data, size_t dataLen)
{
	#ifdef _MSC_VER
	assert(dataLen % 8 == 0, "Data length must be a multiple of 8 bytes");
	#else
	assert(dataLen % 8 == 0);
	#endif
	size_t blocksCount = dataLen / 8;
	uint32_t* blocks = reinterpret_cast<uint32_t*>(data);
	for (size_t i = 0; i < blocksCount; i++)
		encryptBlock(blocks[2 * i], blocks[2 * i + 1]);
}

void Blowfish::decrypt(char* data, size_t dataLen)
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


