#include "Blowfish.h"
#include <algorithm>
#include <cassert>
#include <cstring>
#include "initValues.h"

using namespace std;

static uint64_t fromBytes64(unsigned char const* bytes)
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

uint32_t Blowfish::F(uint32_t in) const
{
	unsigned char bytes[4];
	toBytes(in, bytes);
	return (sBox[0][bytes[0]] + sBox[1][bytes[1]] ^ sBox[2][bytes[2]]) + sBox[3][bytes[3]];
}

void Blowfish::encryptBlock(uint32_t& left, uint32_t& right) const
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

void Blowfish::decryptBlock(uint32_t& left, uint32_t& right) const
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
	memcpy(this->p, BLOWFISHINITP, sizeof(BLOWFISHINITP));
	memcpy(this->sBox, BLOWFISHINITSBOX, sizeof(BLOWFISHINITSBOX));
	keyLen /= 8;
	for (int i = 0; i < 18; ++i)
		p[i] ^= fromBytes(key + (4 * i) % keyLen);
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

void Blowfish::encrypt(unsigned char* data, size_t dataLen) const
{
	size_t blocksCount = dataLen / 8;
	for (size_t i = 0; i < blocksCount; i++)
	{
		uint32_t u1 = fromBytes(data + 8 * i), u2 = fromBytes(data + 8 * i + 4);
		encryptBlock(u1, u2);
		toBytes(u1, data + 8 * i);
		toBytes(u2, data + 8 * i + 4);
	}
}

void Blowfish::decrypt(unsigned char* data, size_t dataLen) const
{
	size_t blocksCount = dataLen / 8;
	for (size_t i = 0; i < blocksCount; i++)
	{
		uint32_t u1 = fromBytes(data + 8 * i), u2 = fromBytes(data + 8 * i + 4);
		decryptBlock(u1, u2);
		toBytes(u1, data + 8 * i);
		toBytes(u2, data + 8 * i + 4);
	}
}

constexpr uint8_t firstExtraByte = 0b10000000;
constexpr uint8_t lastExtraByte = 0b00000001;
constexpr uint8_t onlyExtraByte = 0b10000001;

uint64_t Blowfish::hash(uint8_t const* buf, size_t size)
{
	uint64_t res = size;
	if (size % 8 == 0)
	{
		for (int i = 0; i < size; i += 8)
		{
			uint8_t bytes[8], in[8];
			memcpy(in, buf + i, 8);
			uint64_t in64 = fromBytes64(in);
			toBytes(res, bytes);
			
			Blowfish(bytes, 64).encrypt(in,8);
			res = fromBytes64(in) ^ in64;
		}
	}
	else
	{
		int i;
		for (i = 0; i + 8 < size; i += 8)
		{
			uint8_t bytes[8], in[8];
			memcpy(in, buf + i, 8);
			uint64_t in64 = fromBytes64(in);
			toBytes(res, bytes);

			Blowfish(bytes, 64).encrypt(in, 8);
			res = fromBytes64(in) ^ in64;
		}
		uint8_t bytes[8], in[8];
		memcpy(in, buf + i, size % 8);
		if (size % 8 == 7)
			in[7] = onlyExtraByte;
		else
		{
			in[size % 8] = firstExtraByte;
			for (int j = size % 8 + 1; j < 7; ++j)
				in[j] = 0;
			in[7] = lastExtraByte;
		}
		uint64_t in64 = fromBytes64(in);
		toBytes(res, bytes);

		Blowfish(bytes, 64).encrypt(in, 8);
		res = fromBytes64(in) ^ in64;
	}

	return res;
}


