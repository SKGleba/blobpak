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

#include "crc32.c" // req for blobmath & """RNG"""
#include "aes.c" // req for body enc/dec
#include "blobmath.c" // actual blobpak logic/standard

#define ALIGN16(v) ((v + 0xf) & 0xfffffff0)

// """""random""""" 64 bits
// requires a set rng seed (srand(seed))
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

// find an entry by its name
uint32_t findEntryByName(char* name, void* blobpak, uint32_t pak_size) {
    entry_t temp_entry;
    uint32_t offset = 0;
    while (offset < pak_size) {
        memcpy(&temp_entry, (blobpak + offset), sizeof(entry_t));
        memset(&temp_entry, 0, ENC_ENTRY_ID_SIZE);
        calculateEntryID(&temp_entry, name);
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
        if (encryptEntryDataSize(currentDecryptedSize, entryName) == encryptedEntryDataSize)
            break;
        currentDecryptedSize -= -1;
    }
    return currentDecryptedSize;
}

// create an entry
uint32_t createEntry(uint32_t entryDataSize, char* password, char* entryName, void* entryStart, void** newEntryStart) {
    srand(time(NULL)); // TODO: seed as uarg?
    int randomBlockSize = (rand() % RANDOM_BLOCK_MAX_SIZE) + 1;
    uint32_t entrySize = ALIGN16(entryDataSize) + sizeof(entry_t) + randomBlockSize;
    void* entry = entryStart + (RANDOM_BLOCK_MAX_SIZE - randomBlockSize);

    // add a random data block of random size <= RANDOM_BLOCK_MAX_SIZE before the actual entry
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
    calculateDataKey(password, dataKey, dataIV, entryHead);
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
    
    void* entry = malloc(RANDOM_BLOCK_MAX_SIZE + sizeof(entry_t));
    if (!entry)
        return -2;
    
    if (iput == IPUT_FILE) { // read the data from a file
        fp = fopen(name, "rb");
        if (!fp)
            return -1;
        fseek(fp, 0L, SEEK_END);
        fileSize = ftell(fp);
        entry = realloc(entry, ALIGN16(fileSize) + RANDOM_BLOCK_MAX_SIZE + sizeof(entry_t));
        if (!entry) {
            fclose(fp);
            return -2;
        }
        fileData = entry + RANDOM_BLOCK_MAX_SIZE + sizeof(entry_t);
        memset(fileData, 0, fileSize);
        fseek(fp, 0L, SEEK_SET);
        fread(fileData, fileSize, 1, fp);
        fclose(fp);
    } else { // read the data from stdin
        void* tmp_p = NULL;
        uint32_t tmp_l = 0;
        entry = realloc(entry, STDIN_BUF_INCR + RANDOM_BLOCK_MAX_SIZE + sizeof(entry_t));
        if (!entry)
            return -2;
        fileData = entry + RANDOM_BLOCK_MAX_SIZE + sizeof(entry_t);
        // memset(fileData, 0, STDIN_BUF_INCR); // dont memset, helps the random block
        while (tmp_l = read(fileno(stdin), fileData + fileSize, STDIN_BUF_INCR), tmp_l == STDIN_BUF_INCR) {
            fileSize += STDIN_BUF_INCR;
            tmp_p = realloc(entry, fileSize + STDIN_BUF_INCR + RANDOM_BLOCK_MAX_SIZE + sizeof(entry_t));
            if (!tmp_p) {
                memset(fileData, 0xFF, fileSize);
                return -2;
            }
            entry = tmp_p;
            fileData = entry + RANDOM_BLOCK_MAX_SIZE + sizeof(entry_t);
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
    calculateDataKey(password, dataKey, dataIV, entry);
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
        return -1;
    }

    int ouput = OUPUT_FILE, iput = IPUT_FILE, replace = 0;

    for (int i = 4; i < argc; i++) {
        if (!strcmp("--stdin", argv[i]))
            iput = IPUT_STDIN;
        else if (!strcmp("--stdout", argv[i]))
            ouput = OUPUT_STDOUT;
        else if (!strcmp("--replace", argv[i]))
            replace = 1;
        else if (!strcmp("--view", argv[i]) && !strcmp("get", argv[2]))
            ouput = OUPUT_NICE;
    }

    if (ouput != OUPUT_STDOUT)
        printf(VER_STRING "\n");

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

    if (argc >= 5)
        memset((void*)argv[4], 0xFF, strlen(argv[4]));
    memset((void*)argv[3], 0xFF, strlen(argv[3]));

    return ret;
}

