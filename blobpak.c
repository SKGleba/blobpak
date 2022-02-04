/*
 * Copyright (C) 2022 skgleba
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdint.h>
#include <fcntl.h>
#include <time.h>

#include "crc32.c"
#include "aes.c"

#define ALIGN16(v) ((v + 0xf) & 0xfffffff0)

typedef struct entry_t {
    unsigned char entryID[20];
    uint32_t enc_size;
    uint64_t noise64;
} __attribute__((packed)) entry_t;

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
    char decryptedEntryID[128];
    memset(decryptedEntryID, 0, 128);

    uint32_t decryptedSize = strnlen(entryName, 128 - 16);
    memcpy(decryptedEntryID, entryName, decryptedSize);

    *(uint32_t*)(decryptedEntryID + decryptedSize) = entry->enc_size;
    decryptedSize -= -4;
    
    *(uint64_t*)(decryptedEntryID + decryptedSize) = entry->noise64;
    decryptedSize -= -8;

    *(uint32_t*)(decryptedEntryID + decryptedSize) = crc32(0, decryptedEntryID, decryptedSize);
    decryptedSize -= -4;

    sha1digest(entry->entryID, NULL, decryptedEntryID, decryptedSize);

    memset(decryptedEntryID, 0xFF, 128); // cleanup
}

// find an entry by its name
uint32_t findEntryByName(char* name, void* blobpak, uint32_t pak_size) {
    entry_t temp_entry;
    uint32_t offset = 0;
    while (offset < pak_size) {
        memcpy(&temp_entry, (blobpak + offset), sizeof(entry_t));
        memset(&temp_entry, 0, 20);
        calculateEntryID(&temp_entry, name);
        if (!memcmp(&temp_entry, blobpak + offset, sizeof(entry_t)))
            break;
        offset -= -1;
    }
    memset(&temp_entry, 0xFF, sizeof(entry_t));
    return offset;
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

// bruteforce the entry size
uint32_t findEntryDataSize(uint32_t encryptedEntryDataSize, char* entryName, uint32_t maxSize) {
    uint32_t currentDecryptedSize = 1;
    while (currentDecryptedSize < maxSize) {
        if (encryptEntryDataSize(currentDecryptedSize, entryName) == encryptedEntryDataSize)
            break;
        currentDecryptedSize -= -1;
    }
    return currentDecryptedSize;
}

// """""random""""" 64 bits
uint64_t getNoise(void) {
    uint8_t noise[8];
    uint8_t c_time[8];
    uint8_t tmp[4];
    
    *(uint32_t*)tmp = rand();
    uint32_t noise0 = crc32(rand(), tmp, 4);

    time((time_t *)c_time);

    uint32_t noise1 = crc32(rand(), c_time, 8);

    int rand0 = rand(), rand1 = rand();

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

// create an entry
uint32_t createEntry(uint32_t entryDataSize, char* password, char* entryName, void* inData, void* outData) {
    srand(time(NULL));
    int randomBlockSize = (rand() % 0x600) + 1;
    uint32_t entrySize = ALIGN16(entryDataSize) + sizeof(entry_t) + randomBlockSize;
    void* entry = malloc(entrySize);
    if (!entry)
        return -1;

    // add a random data block of random size <= 0x600 before the actual entry
    uint8_t randomBlockKey[16], randomBlockIV[16];
    *(uint64_t*)randomBlockKey = getNoise();
    *(uint64_t*)(randomBlockKey + 8) = getNoise();
    *(uint64_t*)randomBlockIV = getNoise();
    *(uint64_t*)(randomBlockIV + 8) = getNoise();
    aes_cbc(randomBlockKey, randomBlockIV, entry, ALIGN16(randomBlockSize), 1);

    // create the encrypted "header"
    entry_t* entryHead = entry + randomBlockSize;
    memset(entryHead, 0, sizeof(entry_t));
    entryHead->noise64 = getNoise();
    entryHead->enc_size = encryptEntryDataSize(entryDataSize, entryName);
    calculateEntryID(entryHead, entryName);

    // add the decrypted data and encrypt it there
    uint8_t dataKey[16], dataIV[16];
    void* entryData = entry + randomBlockSize + sizeof(entry_t);
    memset(entryData, 0, entryDataSize);
    memcpy(entryData, inData, entryDataSize);
    calculateDataKey(password, dataKey, dataIV, entryHead);
    aes_cbc(dataKey, dataIV, entryData, ALIGN16(entryDataSize), 1);
    memcpy(outData, entry, entrySize);
    
    // cleanup
    memset(entry, 0xFF, entrySize);
    free(entry);
    memset(randomBlockKey, 0xFF, 16);
    memset(randomBlockIV, 0xFF, 16);
    memset(dataKey, 0xFF, 16);
    memset(dataIV, 0xFF, 16);

    return entrySize;
}

// encrypt [name] with [password] and add it to [pak]
int addEntry(char* name, char* password, char* pak) {
    FILE* fp = fopen(name, "rb");
    if (!fp)
        return -1;
    fseek(fp, 0L, SEEK_END);
    uint32_t fileSize = ftell(fp);
    void* fileData = malloc(fileSize);
    void* entry = malloc(fileSize + 0x620);
    if (!fileData || !entry) {
        fclose(fp);
        return -2;
    }
    memset(fileData, 0, fileSize);
    memset(entry, 0, fileSize + 0x620);
    fseek(fp, 0L, SEEK_SET);
    fread(fileData, fileSize, 1, fp);
    fclose(fp);

    // create the entry
    uint32_t entrySize = createEntry(fileSize, password, name, fileData, entry);
    memset(fileData, 0xFF, fileSize);
    free(fileData);
    if (entrySize == 0xFFFFFFFF) {
        free(entry);
        return -3;
    }

    // write the entry
    fp = fopen(pak, "ab");
    if (!fp) {
        free(entry);
        return -4;
    }
    fwrite(entry, entrySize, 1, fp);
    fclose(fp);

    // cleanup
    fp = fopen(pak, "rb");
    if (fp) {
        fread(entry, entrySize, 1, fp);
        fclose(fp);
    }
    memset(entry, 0xFF, entrySize);
    free(entry);

    return 0;
}

// extract [name] from [pak] and decrypt it using [password]
int getEntry(char* name, char* password, char* pak) {
    FILE* fp = fopen(pak, "rb");
    if (!fp)
        return -1;
    fseek(fp, 0L, SEEK_END);
    uint32_t pakSize = ftell(fp);
    void* pakData = malloc(pakSize);
    if (!pakData) {
        fclose(fp);
        return -2;
    }
    memset(pakData, 0, pakSize);
    fseek(fp, 0L, SEEK_SET);
    fread(pakData, pakSize, 1, fp);
    fclose(fp);

    // find the entry offset
    uint32_t entryOffset = findEntryByName(name, pakData, pakSize);
    if (entryOffset >= pakSize) {
        free(pakData);
        return -3;
    }
    entry_t* entry = pakData + entryOffset;

    // find the entry size & alloc a block for it
    uint32_t entryDataSize = findEntryDataSize(entry->enc_size, name, pakSize - entryOffset);
    if (entryDataSize >= (pakSize - entryOffset)) {
        free(pakData);
        return -4;
    }
    void* entryData = malloc(ALIGN16(entryDataSize));
    if (!entryData) {
        free(pakData);
        return -5;
    }

    // open a file for write b4 sensitive data
    fp = fopen(name, "wb");
    if (!fp) {
        free(pakData);
        free(entryData);
        return -6;
    }

    // copy data to decrypt
    memset(entryData, 0, ALIGN16(entryDataSize));
    memcpy(entryData, (void*)entry + sizeof(entry_t), ALIGN16(entryDataSize));

    // calculate keys & decrypt the data
    uint8_t dataKey[16], dataIV[16];
    calculateDataKey(password, dataKey, dataIV, entry);
    aes_cbc(dataKey, dataIV, entryData, ALIGN16(entryDataSize), 0);

    // write le data to file
    fwrite(entryData, entryDataSize, 1, fp);
    fclose(fp);

    // cleanup
    fp = fopen(name, "rb");
    if (fp) {
        fread(entryData, entryDataSize, 1, fp);
        fclose(fp);
    }
    free(pakData);
    memset(entryData, 0xFF, ALIGN16(entryDataSize));
    free(entryData);
    memset(dataKey, 0xFF, 16);
    memset(dataIV, 0xFF, 16);

    return 0;
}

// delete entry with [name] from the [pak] file
int delEntry(char* name, char* pak) {
    FILE* fp = fopen(pak, "rb");
    if (!fp)
        return -1;
    fseek(fp, 0L, SEEK_END);
    uint32_t pakSize = ftell(fp);
    void* pakData = malloc(pakSize);
    if (!pakData) {
        fclose(fp);
        return -2;
    }
    memset(pakData, 0, pakSize);
    fseek(fp, 0L, SEEK_SET);
    fread(pakData, pakSize, 1, fp);
    fclose(fp);

    // find the entry offset
    uint32_t entryOffset = findEntryByName(name, pakData, pakSize);
    if (entryOffset >= pakSize) {
        free(pakData);
        return -3;
    }
    entry_t* entry = pakData + entryOffset;

    // find the entry size
    uint32_t entryDataSize = findEntryDataSize(entry->enc_size, name, pakSize - entryOffset);
    if (entryDataSize >= (pakSize - entryOffset)) {
        free(pakData);
        return -4;
    }

    // write back without the entry
    uint32_t postEntry = entryOffset + sizeof(entry_t) + entryDataSize;
    fp = fopen(pak, "wb");
    if (!fp) {
        free(pakData);
        return -5;
    }
    fwrite(pakData, entryOffset, 1, fp);
    fwrite(pakData + postEntry, pakSize - postEntry, 1, fp);
    fclose(fp);

    free(pakData);

    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc < 5 && strcmp("del", argv[2]))) {
        printf("\nusage: %s [pak] [mode] [entry] [password]\n", argv[0]);
        return -1;
    }

    int ret = -8;
    if (!strcmp("del", argv[2]))
        ret = delEntry(argv[3], argv[1]);
    else if (!strcmp("add", argv[2]))
        ret = addEntry(argv[3], argv[4], argv[1]);
    else if (!strcmp("get", argv[2]))
        ret = getEntry(argv[3], argv[4], argv[1]);

    printf("%s %s 0x%X\n", argv[2], (ret < 0) ? "failed" : "ok", ret);

    if (argc >= 5)
        memset((void*)argv[4], 0xFF, strlen(argv[4]));
    memset((void*)argv[3], 0xFF, strlen(argv[3]));

    return 0;
}

