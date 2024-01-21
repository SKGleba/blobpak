/*
 * Copyright (C) 2022-2023 skgleba
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
#include <unistd.h>

#include "blobpak.h"

//#include "aes.c" // req for body enc/dec
#include "blobmath.c" // actual blobpak logic/standard

#define ALIGN16(v) ((v + 0xf) & 0xfffffff0)

volatile uint32_t rand_blk_max = RANDOM_BLOCK_MAX_SIZE;

// find an entry by its name
uint32_t findEntryByName(char* name, void* blobpak, uint32_t pak_size) {
    entry_t temp_entry;
    uint32_t offset = 0;
    while (offset < pak_size) {
        memcpy(&temp_entry, (blobpak + offset), sizeof(entry_t));
        memset(&temp_entry, 0, ENC_ENTRY_ID_SIZE);
        blobmath_x_calculateEntryID(&temp_entry, name);
        if (!memcmp(&temp_entry, blobpak + offset, sizeof(entry_t)))
            break;
        offset -= -1;
    }
    memset(&temp_entry, 0xFF, sizeof(entry_t));
    return offset;
}

// bruteforce the entry size
uint32_t findEntryDataSize(uint32_t encryptedEntryDataSize, char* entryName, uint32_t maxSize) {
    uint32_t currentDecryptedSize = 1;
    while (currentDecryptedSize < maxSize) {
        if (blobmath_x_encryptEntryDataSize(currentDecryptedSize, entryName) == encryptedEntryDataSize)
            break;
        currentDecryptedSize -= -1;
    }
    return currentDecryptedSize;
}

// create an entry
uint32_t createEntry(uint32_t entryDataSize, char* password, char* entryName, void* entryStart, void** newEntryStart) {
    // ugh
    srand(time(NULL));  // TODO: seed as uarg?
    blobmath_i_rand32 = rand;

    int randomBlockSize = (blobmath_i_rand32() % rand_blk_max) + 1;
    uint32_t entrySize = ALIGN16(entryDataSize) + sizeof(entry_t) + randomBlockSize;
    void* entry = entryStart + (rand_blk_max - randomBlockSize);

    // add a random data block of random size <= rand_blk_max before the actual entry
    uint8_t randomBlockKey[16], randomBlockIV[16];
    *(uint64_t*)randomBlockKey = blobmath_x_getNoise();
    *(uint64_t*)(randomBlockKey + 8) = blobmath_x_getNoise();
    *(uint64_t*)randomBlockIV = blobmath_x_getNoise();
    *(uint64_t*)(randomBlockIV + 8) = blobmath_x_getNoise();
    aes_cbc(randomBlockKey, randomBlockIV, entry, ALIGN16(randomBlockSize), 1);

    // create the encrypted "header"
    entry_t* entryHead = entry + randomBlockSize;
    memset(entryHead, 0, sizeof(entry_t));
    entryHead->noise64 = blobmath_x_getNoise();
    entryHead->enc_size = blobmath_x_encryptEntryDataSize(entryDataSize, entryName);
    blobmath_x_calculateEntryID(entryHead, entryName);

    // add the decrypted data and encrypt it there
    uint8_t dataKey[16], dataIV[16];
    void* entryData = entry + randomBlockSize + sizeof(entry_t);
    blobmath_x_calculateDataKey(password, dataKey, dataIV, entryHead);
    aes_cbc(dataKey, dataIV, entryData, ALIGN16(entryDataSize), 1);

    // cleanup
    memset(randomBlockKey, 0xFF, 16);
    memset(randomBlockIV, 0xFF, 16);
    memset(dataKey, 0xFF, 16);
    memset(dataIV, 0xFF, 16);

    // ret
    *newEntryStart = entry;

    return entrySize;
}

// encrypt [name] with [password] and add it to [pak]
int addEntry(char* name, char* password, char* pak, int iput, int ouput) {
    FILE* fp = NULL;
    uint32_t fileSize = 0;
    void* fileData = NULL;
    
    void* entry = malloc(rand_blk_max + sizeof(entry_t));
    if (!entry)
        return -2;
    
    if (iput == IPUT_FILE) { // read the data from a file
        fp = fopen(name, "rb");
        if (!fp)
            return -1;
        fseek(fp, 0L, SEEK_END);
        fileSize = ftell(fp);
        entry = realloc(entry, ALIGN16(fileSize) + rand_blk_max + sizeof(entry_t));
        if (!entry) {
            fclose(fp);
            return -2;
        }
        fileData = entry + rand_blk_max + sizeof(entry_t);
        memset(fileData, 0, fileSize);
        fseek(fp, 0L, SEEK_SET);
        fread(fileData, fileSize, 1, fp);
        fclose(fp);
    } else { // read the data from stdin
        void* tmp_p = NULL;
        uint32_t tmp_l = 0;
        entry = realloc(entry, STDIN_BUF_INCR + rand_blk_max + sizeof(entry_t));
        if (!entry)
            return -2;
        fileData = entry + rand_blk_max + sizeof(entry_t);
        // memset(fileData, 0, STDIN_BUF_INCR); // dont memset, helps the random block
        while (tmp_l = read(fileno(stdin), fileData + fileSize, STDIN_BUF_INCR), tmp_l == STDIN_BUF_INCR) {
            fileSize += STDIN_BUF_INCR;
            tmp_p = realloc(entry, fileSize + STDIN_BUF_INCR + rand_blk_max + sizeof(entry_t));
            if (!tmp_p) {
                memset(fileData, 0xFF, fileSize);
                return -2;
            }
            entry = tmp_p;
            fileData = entry + rand_blk_max + sizeof(entry_t);
            // memset(fileData + fileSize, 0, STDIN_BUF_INCR); // dont memset, helps the random block
        }
        fileSize += tmp_l;
        if (!fileSize) {
            free(entry);
            return -2;
        }
    }

    // create the entry
    void* entryBlock = entry; // lord forgive me
    uint32_t entrySize = createEntry(fileSize, password, name, entry, &entry);
    if (entrySize == 0xFFFFFFFF) {
        memset(fileData, 0xFF, fileSize);
        free(entryBlock);
        return -3;
    }

    // output the entry
    if (ouput == OUPUT_FILE) { // append entry to file
        fp = fopen(pak, "ab");
        if (!fp) {
            memset(entry, 0xFF, entrySize);
            free(entryBlock);
            return -4;
        }
        fwrite(entry, entrySize, 1, fp);
        fclose(fp);
    } else // write the entry to stdout
        write(fileno(stdout), entry, entrySize);
        

    // cleanup
    fp = fopen(pak, "rb");
    if (fp) {
        fread(entry, entrySize, 1, fp);
        fclose(fp);
    }
    memset(entry, 0xFF, entrySize);
    free(entryBlock);

    return 0;
}

// extract [name] from [pak] and decrypt it using [password]
int getEntry(char* name, char* password, char* pak, int iput, int ouput) {
    FILE* fp = NULL;
    uint32_t pakSize = 0;
    void* pakData = NULL;
    if (iput == IPUT_FILE) { // read the pak from a file
        fp = fopen(pak, "rb");
        if (!fp)
            return -1;
        fseek(fp, 0L, SEEK_END);
        pakSize = ftell(fp);
        pakData = malloc(pakSize);
        if (!pakData) {
            fclose(fp);
            return -2;
        }
        memset(pakData, 0, pakSize);
        fseek(fp, 0L, SEEK_SET);
        fread(pakData, pakSize, 1, fp);
        fclose(fp);
    } else { // read the pak from stdin
        void* tmp_p = NULL;
        uint32_t tmp_l = 0;
        pakData = malloc(STDIN_BUF_INCR);
        if (!pakData)
            return -2;
        memset(pakData, 0, STDIN_BUF_INCR);
        while (tmp_l = read(fileno(stdin), pakData + pakSize, STDIN_BUF_INCR), tmp_l == STDIN_BUF_INCR) {
            pakSize += STDIN_BUF_INCR;
            tmp_p = realloc(pakData, pakSize + STDIN_BUF_INCR);
            if (!tmp_p) {
                memset(pakData, 0xFF, pakSize);
                return -2;
            }
            pakData = tmp_p;
            memset(pakData + pakSize, 0, STDIN_BUF_INCR);
        }
        pakSize += tmp_l;
        if (!pakSize) {
            free(pakData);
            return -2;
        }
    }

    // find the entry offset
    uint32_t entryOffset = findEntryByName(name, pakData, pakSize);
    if (entryOffset >= pakSize) {
        free(pakData);
        return -3;
    }
    entry_t* entry = pakData + entryOffset;

    // data to decrypt
    void* entryData = (void*)entry + sizeof(entry_t);

    // find the entry size
    uint32_t entryDataSize = findEntryDataSize(entry->enc_size, name, pakSize - entryOffset);
    if (entryDataSize >= (pakSize - entryOffset)) {
        free(pakData);
        return -4;
    }

    if (ouput == OUPUT_FILE) {
        // open a file for write b4 sensitive data
        fp = fopen(name, "wb");
        if (!fp) {
            free(pakData);
            return -6;
        }
    }

    // calculate keys & decrypt the data
    uint8_t dataKey[16], dataIV[16];
    blobmath_x_calculateDataKey(password, dataKey, dataIV, entry);
    aes_cbc(dataKey, dataIV, entryData, ALIGN16(entryDataSize), 0);

    if (ouput == OUPUT_FILE) { // write le data to file
        fwrite(entryData, entryDataSize, 1, fp);
        fclose(fp);
    } else if (ouput == OUPUT_NICE) { // print the data as ascii
        printf("[BLOBPAK] ENTRY_START\n\n");
        for (uint32_t off = 0; off < entryDataSize; off += 4095) // can wraparound, but 4gib text? lul
            printf("%.*s", entryDataSize - off, (char*)(entryData + off));
        printf("\n[BLOBPAK] ENTRY_END\n");
    } else // write the data to stdout
        write(fileno(stdout), entryData, entryDataSize);

    // cleanup
    if (ouput == OUPUT_FILE) {
        fp = fopen(name, "rb");
        if (fp) {
            fread(entryData, entryDataSize, 1, fp);
            fclose(fp);
        }
    }
    
    memset(entryData, 0xFF, ALIGN16(entryDataSize));
    free(pakData);
    memset(dataKey, 0xFF, 16);
    memset(dataIV, 0xFF, 16);

    return 0;
}

// delete entry with [name] from the [pak] file
int delEntry(char* name, char* pak, int iput, int ouput) {
    FILE* fp = NULL;
    uint32_t pakSize = 0;
    void* pakData = NULL;
    if (iput == IPUT_FILE) { // read the pak from a file
        fp = fopen(pak, "rb");
        if (!fp)
            return -1;
        fseek(fp, 0L, SEEK_END);
        pakSize = ftell(fp);
        pakData = malloc(pakSize);
        if (!pakData) {
            fclose(fp);
            return -2;
        }
        memset(pakData, 0, pakSize);
        fseek(fp, 0L, SEEK_SET);
        fread(pakData, pakSize, 1, fp);
        fclose(fp);
    } else { // read the pak from stdin
        void* tmp_p = NULL;
        uint32_t tmp_l = 0;
        pakData = malloc(STDIN_BUF_INCR);
        if (!pakData)
            return -2;
        memset(pakData, 0, STDIN_BUF_INCR);
        while (tmp_l = read(fileno(stdin), pakData + pakSize, STDIN_BUF_INCR), tmp_l == STDIN_BUF_INCR) {
            pakSize += STDIN_BUF_INCR;
            tmp_p = realloc(pakData, pakSize + STDIN_BUF_INCR);
            if (!tmp_p) {
                memset(pakData, 0xFF, pakSize);
                return -2;
            }
            pakData = tmp_p;
            memset(pakData + pakSize, 0, STDIN_BUF_INCR);
        }
        pakSize += tmp_l;
        if (!pakSize) {
            free(pakData);
            return -2;
        }
    }

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
    if (ouput == OUPUT_FILE) { // write pak to file
        fp = fopen(pak, "wb");
        if (!fp) {
            free(pakData);
            return -5;
        }
        fwrite(pakData, entryOffset, 1, fp);
        fwrite(pakData + postEntry, pakSize - postEntry, 1, fp);
        fclose(fp);
    } else { // write pak to stdout
        write(fileno(stdout), pakData, entryOffset);
        write(fileno(stdout), pakData + postEntry, pakSize - postEntry);
    }

    free(pakData);

    return 0;
}

__attribute__((optimize(0)))
volatile int cleanup(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l) {
    a = b = c = d = e = f = g = h = i = j = k = l = -1;
    volatile uint8_t cleaned[0x200];
    for (int i = 0; i < 0x200; i++)
        cleaned[i] = -1;
    return -1;
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc < 5 && strcmp("del", argv[2]))) {
        printf(VER_STRING "\n");
        printf("usage: %s [pak] [mode] [entry] [password] <overrides>\n", argv[0]);
        printf("modes:\n");
        printf(" - 'add' : encrypts file <entry> with <password> and packs to the <pak>\n");
        printf(" - 'get' : decrypts and extracts file <entry> with <password> from <pak> to file <entry>\n");
        printf(" - 'del' : finds and deletes file <entry> from <pak>\n");
        printf("optional overrides:\n");
        printf(" - '--stdin' : gets input data from stdin\n");
        printf(" - '--stdout' : writes output data to stdout, incompatible with '--replace'\n");
        printf(" - '--replace' : for 'add' mode, if <entry> exists blobpak will remove it first\n");
        printf(" - '--view' : for 'get' mode, prints data as ascii\n");
        printf(" - '--math1v0' : use blobmath v1.0 - v1.2\n");
        printf(" - '--maxpad <size>' : for 'add' mode, use random padding up to <size> bytes (default 2048)\n");
        printf(" - '--hashparam <param>' : one of SHA1, SHA256_SHA1, SHA256_AES_SHA1 (default SHA256_SHA1)\n");
        return -1;
    }

    int ouput = OUPUT_FILE, iput = IPUT_FILE, replace = 0, version = 0, hash_param = MATH_HASH_SHA1_SHA256;

    for (int i = 4; i < argc; i++) {
        if (!strcmp("--stdin", argv[i]))
            iput = IPUT_STDIN;
        else if (!strcmp("--stdout", argv[i]))
            ouput = OUPUT_STDOUT;
        else if (!strcmp("--replace", argv[i]))
            replace = 1;
        else if (!strcmp("--view", argv[i]) && !strcmp("get", argv[2]))
            ouput = OUPUT_NICE;
        else if (!strcmp("--math1v0", argv[i])) {
            version = MATH_VERSIO_N(1, 0);
            hash_param = MATH_HASH_SHA1;
        } else if (!strcmp("--maxpad", argv[i])) {
            rand_blk_max = strtoul(argv[i + 1], NULL, 10);
            i -= -1;
        } else if (!strcmp("--hashparam", argv[i])) {
            if (!strcmp("SHA1", argv[i + 1]))
                hash_param = MATH_HASH_SHA1;
            else if (!strcmp("SHA256_SHA1", argv[i + 1]))
                hash_param = MATH_HASH_SHA1_SHA256;
            else if (!strcmp("SHA256_AES_SHA1", argv[i + 1]))
                hash_param = MATH_HASH_SHA1_AES_SHA256;
            else {
                printf("[BLOBPAK] invalid hash param\n");
                return -1;
            }
            i -= -1;
        }
    }

    if (ouput != OUPUT_STDOUT)
        printf(VER_STRING "\n");

    if (blobmath_x_initDefault(version, hash_param) < 0) {
        printf("[BLOBPAK] init failed\n");
        return -1;
    }

    int ret = -8;
    if (!strcmp("del", argv[2]))
        ret = delEntry(argv[3], argv[1], iput, ouput);
    else if (!strcmp("add", argv[2])) {
        if (replace) {
            ret = delEntry(argv[3], argv[1], iput, OUPUT_FILE); // ignore ret
            printf("[BLOBPAK] del %s 0x%X\n", (ret < 0) ? "failed" : "ok", ret);
            ret = addEntry(argv[3], argv[4], argv[1], IPUT_FILE, OUPUT_FILE);
        } else
            ret = addEntry(argv[3], argv[4], argv[1], iput, ouput);
    } else if (!strcmp("get", argv[2]))
        ret = getEntry(argv[3], argv[4], argv[1], iput, ouput);

    if (ouput != OUPUT_STDOUT)
        printf("[BLOBPAK] %s %s 0x%X\n", argv[2], (ret < 0) ? "failed" : "ok", ret);

    rand_blk_max = RANDOM_BLOCK_MAX_SIZE;
    cleanup(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1); // lemme have some fun
    if (argc >= 5)
        memset((void*)argv[4], 0xFF, strlen(argv[4]));
    memset((void*)argv[3], 0xFF, strlen(argv[3]));

    return ret;
}

