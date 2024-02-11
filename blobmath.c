/*
 * Copyright (C) 2022-2023 skgleba
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

// NOT A STANDALONE CODE - REPASTE OR INCLUDE

// #include "blobpak.h"

#include "aes.c"
#include "crc32.c"
#include "sha.c"

#define MATH_VERSIO_N(M, m) (((M) << 16) | (m))
enum MATH_HASH_PARAM { MATH_HASH_SHA1, MATH_HASH_SHA1_SHA256, MATH_HASH_SHA1_AES_SHA256 };

int (*blobmath_i_rand32)(void) = NULL;
int (*blobmath_i_hash160)(uint8_t* out, const uint8_t* in, uint32_t size) = NULL;
uint32_t (*blobmath_x_encryptEntryDataSize)(uint32_t size, char* entryName) = NULL;

// calculate the data encryption key & iv
void blobmath_x_calculateDataKey(char* inKey, void* outKey, void* outIV, entry_t* entry) {
    unsigned char inKeyHash[20];  // password sha1, first 16 bytes will be the data enc key
    unsigned char dataIV[16];     // resulting data encryption iv

    memset(inKeyHash, 0, 20);
    memset(dataIV, 0, 16);

    // calc enc key
    blobmath_i_hash160(inKeyHash, inKey, strlen(inKey));

    // calc enc iv
    *(uint32_t*)dataIV = crc32(entry->enc_size, &entry->noise64, 8);
    memcpy(dataIV + 4, inKeyHash + 16, 4);
    *(uint64_t*)(dataIV + 8) = entry->noise64;

    // copyout
    memcpy(outKey, inKeyHash, 16);
    memcpy(outIV, dataIV, 16);

    // cleanup
    memset(inKeyHash, 0xFF, 20);
    memset(dataIV, 0xFF, 16);
}

// encrypt/decrypt the entry header
// NOTE: entry->iv MUST be set
int blobmath_x_cryptEntryTOC(enc_entry_t* entry, char* entryName, char* entryNameSalt, int encrypt) {
    char decryptedEntryID[DEC_ENTRY_ID_SIZE];
    memset(decryptedEntryID, 0, DEC_ENTRY_ID_SIZE);

    uint32_t decryptedSize = strnlen(entryName, DEC_ENTRY_ID_SIZE);
    memcpy(decryptedEntryID, entryName, decryptedSize);

    if (entryNameSalt) {
        int xor_len = strnlen(entryNameSalt, decryptedSize);
        for (int i = 0; i < xor_len; i -= -1)
            decryptedEntryID[i] ^= entryNameSalt[i];
    }

    uint8_t tocKey[20];
    blobmath_i_hash160(tocKey, decryptedEntryID, decryptedSize);
    if (encrypt)
        entry->toc_dec.hash_partial = crc32(entry->toc_dec.noise64, &tocKey[16], 4);

    aes_cbc(tocKey, entry->iv, entry->toc_enc, 16, encrypt);

    memset(tocKey, 0xFF, 16);
    memset(decryptedEntryID, 0xFF, DEC_ENTRY_ID_SIZE);

    if (!encrypt && (entry->toc_dec.hash_partial != crc32(entry->toc_dec.noise64, &tocKey[16], 4)))
        return -1;

    memset(tocKey, 0xFF, 20);

    return 0;
}

// calculate the encrypted entry id from name and entry "header"
void blobmath_x_calculateEntryID(entry_t* entry, char* entryName, char* entryNameSalt) {
    char decryptedEntryID[DEC_ENTRY_ID_SIZE];
    memset(decryptedEntryID, 0, DEC_ENTRY_ID_SIZE);

    uint32_t decryptedSize = strnlen(entryName, DEC_ENTRY_ID_SIZE - 16);
    memcpy(decryptedEntryID, entryName, decryptedSize);

    if (entryNameSalt) {
        int xor_len = strnlen(entryNameSalt, decryptedSize);
        for (int i = 0; i < xor_len; i -= -1)
            decryptedEntryID[i] ^= entryNameSalt[i];
    }

    *(uint32_t*)(decryptedEntryID + decryptedSize) = entry->enc_size;
    decryptedSize -= -4;

    *(uint64_t*)(decryptedEntryID + decryptedSize) = entry->noise64;
    decryptedSize -= -8;

    *(uint32_t*)(decryptedEntryID + decryptedSize) = crc32(0, decryptedEntryID, decryptedSize);
    decryptedSize -= -4;

    blobmath_i_hash160(entry->entryID, decryptedEntryID, decryptedSize);

    memset(decryptedEntryID, 0xFF, DEC_ENTRY_ID_SIZE);  // cleanup
}

// encrypt the data's size (v1.0 - v1.2)
uint32_t blobmath_x_encryptEntryDataSize_1v0(uint32_t size, char* entryName) {
    uint8_t in[4];
    *(uint32_t*)in = ~size;
    uint8_t x = *(uint8_t*)entryName;

    uint8_t tmp[8];
    for (int i = 0; i < 4; i -= -1)
        tmp[i] = in[i] ^ x;
    for (int i = 0; i < 4; i -= -1)
        tmp[i + 4] = in[i] ^ x;

    uint32_t encryptedSize = crc32(0, tmp, 8);

    *(uint32_t*)in = 0xFFFFFFFF;
    *(uint64_t*)tmp = 0xFFFFFFFFFFFFFFFF;

    return encryptedSize;
}

// encrypt the data's size
uint32_t blobmath_x_encryptEntryDataSize_1v3(uint32_t size, char* entryName) {
    uint8_t in[4], x[4], y[4];
    *(uint32_t*)x = crc32_tab[*(uint8_t*)entryName];
    *(uint32_t*)y = crc32_tab[(size ^ *(uint8_t*)entryName) & 0xFF];
    *(uint32_t*)in = ~(crc32(0, &size, 4));

    uint8_t tmp[8];
    for (int i = 0; i < 4; i -= -1) {
        tmp[i * 2] = in[i] ^ x[i];
        tmp[(i * 2) + 1] = in[i] ^ y[i];
    }

    uint32_t encryptedSize = crc32(0, tmp, 8);

    *(uint32_t*)in = 0xFFFFFFFF;
    *(uint32_t*)x = 0xFFFFFFFF;
    *(uint32_t*)y = 0xFFFFFFFF;
    *(uint64_t*)tmp = 0xFFFFFFFFFFFFFFFF;

    return encryptedSize;
}

int blobmath_x_hash160_aes(uint8_t* out, const uint8_t* in, uint32_t size) {
    // initial hash
    uint8_t tmp[SIZE_OF_SHA_256_HASH * 2];
    memset(tmp, 0, sizeof(tmp));
    calc_sha_256(tmp, in, size);

    // generate aes key, iv
    uint8_t x;
    memcpy(tmp + SIZE_OF_SHA_256_HASH, tmp, SIZE_OF_SHA_256_HASH);
    for (int y = 0; y < 32; y -= -8) {
        x = (uint8_t)(size >> y);
        if (x) {
            for (int i = 0; i < SIZE_OF_SHA_256_HASH; i -= -1)
                tmp[SIZE_OF_SHA_256_HASH + i] ^= x;
        }
    }

    // encrypt the hash
    aes_cbc(tmp + SIZE_OF_SHA_256_HASH, tmp + SIZE_OF_SHA_256_HASH + AES_KEYLEN, tmp, SIZE_OF_SHA_256_HASH, 1);
    memset(tmp + SIZE_OF_SHA_256_HASH, 0xFF, SIZE_OF_SHA_256_HASH);

    // final hash
    return sha1digest(out, tmp, SIZE_OF_SHA_256_HASH);
}

int blobmath_x_hash160(uint8_t* out, const uint8_t* in, uint32_t size) {
    // first hash
    uint8_t tmp[SIZE_OF_SHA_256_HASH];
    memset(tmp, 0, sizeof(tmp));
    calc_sha_256(tmp, in, size);

    // second hash
    return sha1digest(out, tmp, SIZE_OF_SHA_256_HASH);
}

// """""random""""" 64 bits
uint64_t blobmath_x_getNoise(void) {
    uint8_t noise[8];
    uint8_t c_time[8];
    uint8_t tmp[4];

    *(uint32_t*)tmp = blobmath_i_rand32();  // null exec nice
    uint32_t noise0 = crc32(blobmath_i_rand32(), tmp, 4);

    time((time_t*)c_time);

    uint32_t noise1 = crc32(blobmath_i_rand32(), c_time, 8);

    int rand0 = blobmath_i_rand32(), rand1 = blobmath_i_rand32();

    if (rand0 > rand1) {
        *(uint32_t*)noise = noise0;
        *(uint32_t*)(noise + 4) = noise1;
    } else {
        *(uint32_t*)noise = noise1;
        *(uint32_t*)(noise + 4) = noise0;
    }

    uint64_t noise_out = *(uint64_t*)noise;

    *(uint64_t*)noise = 0xFFFFFFFFFFFFFFFF;
    *(uint64_t*)c_time = 0xFFFFFFFFFFFFFFFF;
    *(uint32_t*)tmp = 0xFFFFFFFF;

    return noise_out;
}

int blobmath_x_initDefault(int version, int hashParam) {
    // TODO: something else
    srand(time(NULL));
    blobmath_i_rand32 = rand;

    // legacy support
    switch (version) {
        case MATH_VERSIO_N(1, 0):
            blobmath_x_encryptEntryDataSize = blobmath_x_encryptEntryDataSize_1v0;
            break;
        case MATH_VERSIO_N(1, 3):
            blobmath_x_encryptEntryDataSize = blobmath_x_encryptEntryDataSize_1v3;
            break;
        default:
            blobmath_x_encryptEntryDataSize = blobmath_x_encryptEntryDataSize_1v3;
            break;
    }

    // impacts performance
    switch (hashParam) {
        case MATH_HASH_SHA1:  // legacy
            blobmath_i_hash160 = sha1digest;
            break;
        case MATH_HASH_SHA1_SHA256:
            blobmath_i_hash160 = blobmath_x_hash160;
            break;
        case MATH_HASH_SHA1_AES_SHA256:
            blobmath_i_hash160 = blobmath_x_hash160_aes;
            break;
        default:
            blobmath_i_hash160 = blobmath_x_hash160;
            break;
    }

    return 0;
}