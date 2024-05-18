#pragma once
#include <cstdint>
#include <cstddef>

class Blowfish
{
private:
    uint32_t p[18];
    uint32_t sBox[4][256];

    uint32_t F(uint32_t in) const;
    void encryptBlock(uint32_t& left, uint32_t& right) const;
    void decryptBlock(uint32_t& left, uint32_t& right) const;

public:
    Blowfish(unsigned char const* key, size_t keyLen);
    void encrypt(unsigned char* data, size_t dataLen) const;
    void decrypt(unsigned char* data, size_t dataLen) const;
    static uint64_t hash(uint8_t const* buf, size_t size);
};

