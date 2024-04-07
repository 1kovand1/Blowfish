#include "Blowfish.h"
#include <algorithm>
#include <cassert>

static uint32_t fromBytes(unsigned char const* bytes)
{
	return bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3];
}

static void toBytes(uint32_t num, unsigned char* bytes)
{
	for (int i = 3; i >= 0; i--)
	{
		bytes[i] = num & 0xff;
		num >>= 8;
	}
}

uint32_t Blowfish::F(uint32_t in)
{
	unsigned char bytes[4];
	toBytes(in, bytes);
	return (sBox[0][bytes[0]] + sBox[1][bytes[1]] ^ sBox[2][bytes[2]]) + sBox[3][bytes[3]];
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
	keyLen /= 8;
	for (int i = 0; i < 18; ++i)
		p[i] ^= fromBytes(key + (4 * i % keyLen));
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
	for (size_t i = 0; i < blocksCount; i++)
	{
		uint32_t u1 = fromBytes(data + 8 * i), u2 = fromBytes(data + 8 * i + 4);
		encryptBlock(u1, u2);
		toBytes(u1, data + 8 * i);
		toBytes(u2, data + 8 * i + 4);
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
	for (size_t i = 0; i < blocksCount; i++)
	{
		uint32_t u1 = fromBytes(data + 8 * i), u2 = fromBytes(data + 8 * i + 4);
		decryptBlock(u1, u2);
		toBytes(u1, data + 8 * i);
		toBytes(u2, data + 8 * i + 4);
	}
}


