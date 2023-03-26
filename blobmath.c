/*
 * Copyright (C) 2022-2023 skgleba
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

 // NOT A STANDALONE CODE - REPASTE OR INCLUDE

// #include "blobpak.h"

int sha1digest(uint8_t* digest, char* hexdigest, const uint8_t* data, size_t databytes);

// calculate the data encryption key & iv
void calculateDataKey(char* inKey, void* outKey, void* outIV, entry_t* entry) {
    unsigned char inKeyHash[20]; // password sha1, first 16 bytes will be the data enc key
    unsigned char dataIV[16]; // resulting data encryption iv

    memset(inKeyHash, 0, 20);
    memset(dataIV, 0, 16);

    // calc enc key
    sha1digest(inKeyHash, NULL, inKey, strlen(inKey));

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

// calculate the encrypted entry id from name and entry "header"
void calculateEntryID(entry_t* entry, char* entryName) {
    char decryptedEntryID[DEC_ENTRY_ID_SIZE];
    memset(decryptedEntryID, 0, DEC_ENTRY_ID_SIZE);

    uint32_t decryptedSize = strnlen(entryName, DEC_ENTRY_ID_SIZE - 16);
    memcpy(decryptedEntryID, entryName, decryptedSize);

    *(uint32_t*)(decryptedEntryID + decryptedSize) = entry->enc_size;
    decryptedSize -= -4;

    *(uint64_t*)(decryptedEntryID + decryptedSize) = entry->noise64;
    decryptedSize -= -8;

    *(uint32_t*)(decryptedEntryID + decryptedSize) = crc32(0, decryptedEntryID, decryptedSize);
    decryptedSize -= -4;

    sha1digest(entry->entryID, NULL, decryptedEntryID, decryptedSize);

    memset(decryptedEntryID, 0xFF, DEC_ENTRY_ID_SIZE); // cleanup
}

// encrypt the data's size
uint32_t encryptEntryDataSize(uint32_t size, char* entryName) {
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

// code based on tiny-sha1.c
int sha1digest(uint8_t* digest, char* hexdigest, const uint8_t* data, size_t databytes) {
#define SHA1ROTATELEFT(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

    uint32_t W[80];
    uint32_t H[] = { 0x67452301,
                    0xEFCDAB89,
                    0x98BADCFE,
                    0x10325476,
                    0xC3D2E1F0 };
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f = 0;
    uint32_t k = 0;

    uint32_t idx;
    uint32_t lidx;
    uint32_t widx;
    uint32_t didx = 0;

    int32_t wcount;
    uint32_t temp;
    uint64_t databits = ((uint64_t)databytes) * 8;
    uint32_t loopcount = (databytes + 8) / 64 + 1;
    uint32_t tailbytes = 64 * loopcount - databytes;
    uint8_t datatail[128] = { 0 };

    if (!digest && !hexdigest)
        return -1;

    if (!data)
        return -1;

    datatail[0] = 0x80;
    datatail[tailbytes - 8] = (uint8_t)(databits >> 56 & 0xFF);
    datatail[tailbytes - 7] = (uint8_t)(databits >> 48 & 0xFF);
    datatail[tailbytes - 6] = (uint8_t)(databits >> 40 & 0xFF);
    datatail[tailbytes - 5] = (uint8_t)(databits >> 32 & 0xFF);
    datatail[tailbytes - 4] = (uint8_t)(databits >> 24 & 0xFF);
    datatail[tailbytes - 3] = (uint8_t)(databits >> 16 & 0xFF);
    datatail[tailbytes - 2] = (uint8_t)(databits >> 8 & 0xFF);
    datatail[tailbytes - 1] = (uint8_t)(databits >> 0 & 0xFF);

    for (lidx = 0; lidx < loopcount; lidx++) {

        memset(W, 0, 80 * sizeof(uint32_t));

        for (widx = 0; widx <= 15; widx++) {
            wcount = 24;

            while (didx < databytes && wcount >= 0) {
                W[widx] += (((uint32_t)data[didx]) << wcount);
                didx++;
                wcount -= 8;
            }

            while (wcount >= 0) {
                W[widx] += (((uint32_t)datatail[didx - databytes]) << wcount);
                didx++;
                wcount -= 8;
            }
        }

        for (widx = 16; widx <= 31; widx++) {
            W[widx] = SHA1ROTATELEFT((W[widx - 3] ^ W[widx - 8] ^ W[widx - 14] ^ W[widx - 16]), 1);
        }
        for (widx = 32; widx <= 79; widx++) {
            W[widx] = SHA1ROTATELEFT((W[widx - 6] ^ W[widx - 16] ^ W[widx - 28] ^ W[widx - 32]), 2);
        }

        a = H[0];
        b = H[1];
        c = H[2];
        d = H[3];
        e = H[4];

        for (idx = 0; idx <= 79; idx++) {
            if (idx <= 19) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (idx >= 20 && idx <= 39) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (idx >= 40 && idx <= 59) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else if (idx >= 60 && idx <= 79) {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            temp = SHA1ROTATELEFT(a, 5) + f + e + k + W[idx];
            e = d;
            d = c;
            c = SHA1ROTATELEFT(b, 30);
            b = a;
            a = temp;
        }

        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
    }

    if (digest) {
        for (idx = 0; idx < 5; idx++) {
            digest[idx * 4 + 0] = (uint8_t)(H[idx] >> 24);
            digest[idx * 4 + 1] = (uint8_t)(H[idx] >> 16);
            digest[idx * 4 + 2] = (uint8_t)(H[idx] >> 8);
            digest[idx * 4 + 3] = (uint8_t)(H[idx]);
        }
    }

    if (hexdigest) {
        snprintf(hexdigest, 41, "%08x%08x%08x%08x%08x",
            H[0], H[1], H[2], H[3], H[4]);
    }

    return 0;
}