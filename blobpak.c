/*
 * Copyright (C) 2022-2024 skgleba
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "blobpak.h"

// #include "aes.c" // req for body enc/dec
#include "blobmath.c"  // actual blobpak logic/standard

#define ALIGN16(v) ((v + 0xf) & 0xfffffff0)

volatile int enchdr = 0;
volatile uint32_t rand_blk_max = RANDOM_BLOCK_MAX_SIZE;

/**
 * @brief Finds an entry in the blobpak by its name.
 * This function searches for an entry with the specified name in the blobpak.
 * It uses a brute force approach to find the entry by iterating through the blobpak byte by byte.
 *
 * @param name The name of the entry to find.
 * @param name_salt Optional salt that is XORed with the entry name before hashing.
 * @param blobpak Pointer to the blobpak data.
 * @param pak_size The size of the blobpak in bytes.
 * @return The offset of the found entry in the blobpak, or pak_size if not found.
 */
uint32_t findEntryByName(char* name, char* name_salt, void* blobpak, uint32_t pak_size) {
    entry_t temp_entry;
    uint32_t offset = 0;
    while (offset < pak_size) {
        memcpy(&temp_entry, (blobpak + offset), sizeof(entry_t));
        if (enchdr) {
            if (!blobmath_x_cryptEntryTOC((enc_entry_t*)&temp_entry, name, name_salt, 0))
                break;
        } else {
            memset(&temp_entry, 0, ENC_ENTRY_ID_SIZE);
            blobmath_x_calculateEntryID(&temp_entry, name, name_salt);
            if (!memcmp(&temp_entry, blobpak + offset, sizeof(entry_t)))
                break;
        }
        offset -= -1;
    }
    memset(&temp_entry, 0xFF, sizeof(entry_t));
    return offset;
}

/**
 * @brief Finds the decrypted size of an entry in a blobpak.
 * This function uses a brute force approach to find the decrypted size of an entry in a blobpak.
 * It iterates through possible sizes starting from 1 and checks if the encrypted size
 * matches the given encrypted entry data size. Once a match is found, the function returns the
 * decrypted size.
 *
 * @param encryptedEntryDataSize The encrypted size of the entry data.
 * @param entryName The name of the entry.
 * @param maxSize The maximum size to consider during the search.
 * @return The decrypted size of the entry, or maxSize if no match is found.
 */
uint32_t findEntryDataSize(uint32_t encryptedEntryDataSize, char* entryName, uint32_t maxSize) {
    uint32_t currentDecryptedSize = 1;
    while (currentDecryptedSize < maxSize) {
        if (blobmath_x_encryptEntryDataSize(currentDecryptedSize, entryName) == encryptedEntryDataSize)
            break;
        currentDecryptedSize -= -1;
    }
    return currentDecryptedSize;
}

/**
 * @brief Creates an entry at the given address.
 * First, a random-sized block of random data is generated.
 * Then, the entry header is created and, optionally, encrypted.
 * Finally, the entry data is encrypted in place using a key & iv derived from the password.
 *
 * @param entryDataSize The size of the entry data.
 * @param password The password used for data encryption.
 * @param entryName The name of the entry.
 * @param entryNameSalt Optional salt for the entry name.
 * @param entryStart Entry buffer containing the entry data at (rand_blk_max + sizeof(entry_t)).
 * @param newEntryStart The start address of the entry inside the entry buffer.
 * @return The size of the created entry.
 */
// create an entry
uint32_t createEntry(uint32_t entryDataSize, char* password, char* entryName, char* entryNameSalt, void* entryStart, void** newEntryStart) {
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
    if (enchdr) {  // prep IV for cbc
        *(uint64_t*)entryHead->entryID = blobmath_x_getNoise();
        *(uint64_t*)(entryHead->entryID + 8) = blobmath_x_getNoise();
    } else
        blobmath_x_calculateEntryID(entryHead, entryName, entryNameSalt);

    // add the decrypted data and encrypt it there
    uint8_t dataKey[16], dataIV[16];
    void* entryData = entry + randomBlockSize + sizeof(entry_t);
    blobmath_x_calculateDataKey(password, dataKey, dataIV, entryHead);
    aes_cbc(dataKey, dataIV, entryData, ALIGN16(entryDataSize), 1);

    // encrypt the entry header (optional)
    if (enchdr)
        blobmath_x_cryptEntryTOC((enc_entry_t*)entryHead, entryName, entryNameSalt, 1);

    // cleanup
    memset(randomBlockKey, 0xFF, 16);
    memset(randomBlockIV, 0xFF, 16);
    memset(dataKey, 0xFF, 16);
    memset(dataIV, 0xFF, 16);

    // ret
    *newEntryStart = entry;

    return entrySize;
}

/**
 * @brief Creates an entry and appends it to the blobpak.
 *
 * @param name The name/path of the file to be encrypted and added to the package.
 * @param nameSalt The salt value used for obfuscating the file name.
 * @param password The password used for encrypting the file data.
 * @param pak The blobpak to which the encrypted entry will be appended.
 * @param iput The input source of the file data (IPUT_FILE or IPUT_STDIN).
 * @param ouput The output destination for the encrypted entry (OUPUT_FILE or OUPUT_STDOUT).
 * @return 0 if the entry was successfully added, a negative value indicating an error otherwise.
 */
// encrypt [name] with [password] and add it to [pak]
int addEntry(char* name, char* nameSalt, char* password, char* pak, int iput, int ouput) {
    FILE* fp = NULL;
    uint32_t fileSize = 0;
    void* fileData = NULL;

    void* entry = malloc(rand_blk_max + sizeof(entry_t));
    if (!entry)
        return -2;

    if (iput == IPUT_FILE) {  // read the data from a file
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
    } else {  // read the data from stdin
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
    void* entryBlock = entry;  // lord forgive me
    uint32_t entrySize = createEntry(fileSize, password, name, nameSalt, entry, &entry);
    if (entrySize == 0xFFFFFFFF) {
        memset(fileData, 0xFF, fileSize);
        free(entryBlock);
        return -3;
    }

    // output the entry
    if (ouput == OUPUT_FILE) {  // append entry to file
        fp = fopen(pak, "ab");
        if (!fp) {
            memset(entry, 0xFF, entrySize);
            free(entryBlock);
            return -4;
        }
        fwrite(entry, entrySize, 1, fp);
        fclose(fp);
    } else  // write the entry to stdout
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

/**
 * @brief Finds, extracts, decrypts, and outputs an entry from a blobpak.
 *
 * @param name The name of the entry to extract.
 * @param nameSalt The salt used for obfuscating the entry name.
 * @param password The password used for decrypting the entry data.
 * @param pak The path to the blobpak containing the entry.
 * @param iput The input source, either IPUT_FILE or IPUT_STDIN.
 * @param ouput The output destination, either OUPUT_FILE, OUPUT_NICE, or OUPUT_STDOUT.
 *   @note The output file will be overwritten if it already exists.
 * @return 0 if successful, or a negative value indicating an error.
 */
int getEntry(char* name, char* nameSalt, char* password, char* pak, int iput, int ouput) {
    FILE* fp = NULL;
    uint32_t pakSize = 0;
    void* pakData = NULL;
    if (iput == IPUT_FILE) {  // read the pak from a file
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
    } else {  // read the pak from stdin
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
    uint32_t entryOffset = findEntryByName(name, nameSalt, pakData, pakSize);
    if (entryOffset >= pakSize) {
        free(pakData);
        return -3;
    }
    entry_t* entry = pakData + entryOffset;
    if (enchdr)  // decrypt the entry header
        blobmath_x_cryptEntryTOC((enc_entry_t*)entry, name, nameSalt, 0);

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

    if (ouput == OUPUT_FILE) {  // write le data to file
        fwrite(entryData, entryDataSize, 1, fp);
        fclose(fp);
    } else if (ouput == OUPUT_NICE) {  // print the data as ascii
        printf("[BLOBPAK] ENTRY_START\n\n");
        for (uint32_t off = 0; off < entryDataSize; off += 4095)  // can wraparound, but 4gib text? lul
            printf("%.*s", entryDataSize - off, (char*)(entryData + off));
        printf("\n[BLOBPAK] ENTRY_END\n");
    } else  // write the data to stdout
        write(fileno(stdout), entryData, entryDataSize);

    // cleanup
    if (ouput == OUPUT_FILE) {
        fp = fopen(name, "rb");
        if (fp) {
            fread(entryData, entryDataSize, 1, fp);
            fclose(fp);
        }
    }

    memset(entry, 0xFF, sizeof(entry_t));
    memset(entryData, 0xFF, ALIGN16(entryDataSize));
    free(pakData);
    memset(dataKey, 0xFF, 16);
    memset(dataIV, 0xFF, 16);

    return 0;
}

/**
 * @brief Deletes an entry with the specified name from the blobpak container.
 *
 * @param name The name of the entry to be deleted.
 * @param nameSalt The salt used for obfuscation of the entry name.
 * @param pak The path to the blobpak containing the entry.
 * @param iput The input source (IPUT_FILE or IPUT_STDIN).
 * @param ouput The output destination for the resulting blobpak (OUPUT_FILE or OUPUT_STDOUT).
 * @return 0 if the entry is successfully deleted, a negative value indicating an error otherwise.
 */
int delEntry(char* name, char* nameSalt, char* pak, int iput, int ouput) {
    FILE* fp = NULL;
    uint32_t pakSize = 0;
    void* pakData = NULL;
    if (iput == IPUT_FILE) {  // read the pak from a file
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
    } else {  // read the pak from stdin
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
    uint32_t entryOffset = findEntryByName(name, nameSalt, pakData, pakSize);
    if (entryOffset >= pakSize) {
        memset(pakData, 0xFF, pakSize);
        free(pakData);
        return -3;
    }
    entry_t* entry = pakData + entryOffset;
    if (enchdr)  // decrypt the entry header
        blobmath_x_cryptEntryTOC((enc_entry_t*)entry, name, nameSalt, 0);

    // find the entry size
    uint32_t entryDataSize = findEntryDataSize(entry->enc_size, name, pakSize - entryOffset);
    if (entryDataSize >= (pakSize - entryOffset)) {
        memset(pakData, 0xFF, pakSize);
        free(pakData);
        return -4;
    }

    // write back without the entry
    uint32_t postEntry = entryOffset + sizeof(entry_t) + entryDataSize;
    if (ouput == OUPUT_FILE) {  // write pak to file
        fp = fopen(pak, "wb");
        if (!fp) {
            memset(pakData, 0xFF, pakSize);
            free(pakData);
            return -5;
        }
        fwrite(pakData, entryOffset, 1, fp);
        fwrite(pakData + postEntry, pakSize - postEntry, 1, fp);
        fclose(fp);
    } else {  // write pak to stdout
        write(fileno(stdout), pakData, entryOffset);
        write(fileno(stdout), pakData + postEntry, pakSize - postEntry);
    }

    memset(pakData, 0xFF, pakSize);
    free(pakData);

    return 0;
}

/**
 * @brief Performs cleanup operations.
 * Clean the stack and heap by overwriting the input arguments and some local variables with 0xFF.
 *
 * @return -1 indicating the cleanup operation is complete.
 */
__attribute__((optimize(0))) volatile int cleanup(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l) {
    a = b = c = d = e = f = g = h = i = j = k = l = -1;
    volatile uint8_t cleaned[0x200];
    for (int i = 0; i < 0x200; i++)
        cleaned[i] = -1;
    return -1;
}

/**
 * @brief Main function for the blobpak manager.
 * Parse the arguments, initialize the blobmath library, and call the appropriate function based on the mode.
 * At the end, clean up the input arguments and some local variables.
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of strings representing the container location, mode, entry path, password, and optional overrides.
 *   @warning This function expects the argv array of strings to be writable.
 * @return The exit status of the operation.
 */
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
        printf(" - '--enchdr' : encrypt the entry header\n");
        printf(" - '--namesalt <salt>' : use <salt> as the entry name salt\n");
        printf(" - '--pwdsalt <salt>' : use <salt> as the password salt\n");
        return -1;
    }

    char *name_salt = NULL, *password_salt = NULL;
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
        } else if (!strcmp("--enchdr", argv[i]))
            enchdr = 1;
        else if (!strcmp("--namesalt", argv[i])) {
            name_salt = argv[i + 1];
            i -= -1;
        } else if (!strcmp("--pwdsalt", argv[i])) {
            // xor salt with the password
            password_salt = argv[i + 1];
            int xor_len = strnlen(password_salt, strlen(argv[4]));
            for (int y = 0; y < xor_len; y -= -1)
                argv[4][y] ^= password_salt[y];
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
        ret = delEntry(argv[3], name_salt, argv[1], iput, ouput);
    else if (!strcmp("add", argv[2])) {
        if (replace) {
            ret = delEntry(argv[3], name_salt, argv[1], iput, OUPUT_FILE);  // ignore ret
            printf("[BLOBPAK] del %s 0x%X\n", (ret < 0) ? "failed" : "ok", ret);
            ret = addEntry(argv[3], name_salt, argv[4], argv[1], IPUT_FILE, OUPUT_FILE);
        } else
            ret = addEntry(argv[3], name_salt, argv[4], argv[1], iput, ouput);
    } else if (!strcmp("get", argv[2]))
        ret = getEntry(argv[3], name_salt, argv[4], argv[1], iput, ouput);

    if (ouput != OUPUT_STDOUT)
        printf("[BLOBPAK] %s %s 0x%X\n", argv[2], (ret < 0) ? "failed" : "ok", ret);

    rand_blk_max = RANDOM_BLOCK_MAX_SIZE;
    enchdr = 0;
    cleanup(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1);  // lemme have some fun
    if (argc >= 5)
        memset((void*)argv[4], 0xFF, strlen(argv[4]));
    memset((void*)argv[3], 0xFF, strlen(argv[3]));
    if (name_salt)
        memset((void*)name_salt, 0xFF, strlen(name_salt));
    if (password_salt)
        memset((void*)password_salt, 0xFF, strlen(password_salt));

    return ret;
}
