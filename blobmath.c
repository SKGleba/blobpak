/*
 * Copyright (C) 2022-2024 skgleba
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

/**
 * @brief Calculates the data encryption key and initialization vector (IV) for encryption.
 * The data encryption key is the first 16 bytes of the hash160 of the input key.
 * The IV is structured as follows:
 *  * the CRC32 of the encrypted data size XORed with noise64.
 *  * the last 4 bytes of the hash160 of the input key.
 *  * the noise64 field of the entry.
 *
 * @param inKey The input key/password used for encryption.
 * @param outKey The output buffer to store the data encryption key.
 * @param outIV The output buffer to store the initialization vector.
 * @param entry The entry containing set enc_size and noise64 fields.
 */
void blobmath_x_calculateDataKey(char* inKey, void* outKey, void* outIV, entry_t* entry) {
    unsigned char inKeyHash[20];  // password hash160, first 16 bytes will be the data enc key
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

/**
 * @brief Encrypts or decrypts the entry header.
 * The entry name is truncated to 128 bytes, XORed with the name salt if provided, and hashed using hash160.
 *  * The first 16 bytes of the hash160 are used as the key for the AES encryption.
 *  * The CRC32 of the last 4 bytes of the hash160 are stored in the encrypted entry header.
 *    * This is used to verify the validity of the decrypted entry header.
 * The encryption used is AES-128-CBC.
 *
 * @warning The entry->iv field MUST be set before calling this function.
 *
 * @param entry The entry to be encrypted or decrypted.
 * @param entryName The name of the entry.
 * @param entryNameSalt The salt used for XOR encryption. Can be NULL.
 * @param encrypt Flag indicating whether to encrypt or decrypt the entry.
 * @return 0 if the decrypted block is valid, -1 if the decrypted block is invalid.
 */
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

/**
 * @brief Calculates the encrypted entry ID from the given entry, entry name, and entry name salt.
 * The entry ID is calculated as follows:
 *  * The entry name is truncated to up to 112 bytes and XORed with the entry name salt if provided.
 *  * The encrypted data size is appended to the entry name.
 *  * The noise64 field is appended to the entry name.
 *  * The CRC32 of the resulting entry name is calculated and appended to the entry name.
 *  * The resulting entry name is hashed using hash160.
 * The resulting entry ID is stored in the entry->entryID field.
 *
 * @param entry         Pointer to the entry structure.
 * @param entryName     Pointer to the entry name string.
 * @param entryNameSalt Pointer to the entry name salt string.
 */
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

/**
 * @brief Encrypts the size of the data using the given entry name.
 * This function was used from version 1.0 to 1.2 of the blobpak format.
 * The size is first bitwise negated and then XORed with the first byte of the entry name.
 * The resulting value is then CRC32 hashed.
 *
 * @warning This algorithm is too fast and therefore opens the door to brute force attacks (entry mapping by probable size).
 *
 * @param size The size of the data to be encrypted.
 * @param entryName The name of the entry used for encryption.
 * @return The encrypted size of the data.
 */
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

/**
 * @brief Encrypts the data's size using the given entry name.
 * Firstly, the size's CRC32 is calculated and bitwise negated.
 * Then, it is expanded to 8 bytes by XORing each byte with:
 *  * the CRC32 LUT entry for the first byte of the entry name.
 *  * the CRC32 LUT entry for the first byte of size XORed with the first byte of the entry name.
 * The resulting 8-byte value is then CRC32 hashed.
 *
 * @warning It is still possible to brute force the entry mapping by probable size, but it is much harder than in the previous version.
 *
 * @param size The size of the data to be encrypted.
 * @param entryName The name of the entry associated with the data.
 * @return The encrypted size of the data.
 */
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

/**
 * @brief Calculates the hash160 of the input data with an additional AES encryption step.
 * The first round is a SHA-256 hash of the input data.
 * Then, the SHA-256 hash is used to calculate the AES key and IV by XORing it with the size of the input data.
 * @todo Is this safe?
 * The SHA-256 hash is then encrypted using the generated AES key and IV.
 * Finally, the SHA-1 hash of the encrypted SHA-256 hash is calculated and stored in the output buffer.
 *
 * @param out The 20-byte output buffer to store the hash160 result.
 * @param in The input data to be hashed.
 * @param size The size of the input data.
 * @return Returns 0 if the hash160 calculation is successful, otherwise returns an error code.
 */
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

/**
 * @brief Calculates the hash160 of the input data using two rounds of hashing.
 * The first round is a SHA-256 hash of the input data.
 * The second round is a SHA-1 hash of the SHA-256 hash.
 * The resulting hash is stored in the output buffer.
 *
 * @param out The 20-byte output buffer to store the hash160 result.
 * @param in The input data to be hashed.
 * @param size The size of the input data.
 * @return 0 if the hash160 calculation is successful, -1 otherwise.
 */
int blobmath_x_hash160(uint8_t* out, const uint8_t* in, uint32_t size) {
    // first hash
    uint8_t tmp[SIZE_OF_SHA_256_HASH];
    memset(tmp, 0, sizeof(tmp));
    calc_sha_256(tmp, in, size);

    // second hash
    return sha1digest(out, tmp, SIZE_OF_SHA_256_HASH);
}

/**
 * @brief Generates a """"random""""" 64-bit value.
 * The value is generated using the following steps:
 *  * Half of the value is generated using the CRC32 of a random 32-bit value and another random 32-bit value.
 *  * The other half of the value is generated using the CRC32 of the current time and a random 32-bit value.
 *  * The two halves are combined into a 64-bit value, with their order determined by the comparison of two random 32-bit values.
 *
 * @todo Does the CRC32 make it less random assuming blobmath_i_rand32 is a good PRNG?
 * @warning The blobmath_i_rand32 function pointer must be set before calling this function.
 *
 * @return The generated 64-bit value.
 */
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

/**
 * @brief Initializes the blobmath "library".
 * The default settings are as follows:
 *  * rand32 is the standard c rand function.
 *    @todo something else, please lmao
 *  * hash160 is SHA-1(SHA-256(data))
 *  * latest data size encryption algorithm
 * The version and hashParam parameters can be used to override the default settings.
 *
 * @param version The version of the blobmath library, in the format MATH_VERSION(M, m).
 * @param hashParam The hashing algorithm of hash160, from the MATH_HASH_PARAM enum.
 * @return 0 if successful, otherwise an error code.
 */
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