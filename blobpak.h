/*
 * Copyright (C) 2022-2023 skgleba
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifndef __BLOBPAK_H__
#define __BLOBPAK_H__

#define ENC_ENTRY_ID_SIZE 20
#define DEC_ENTRY_ID_SIZE 128
#define STDIN_BUF_INCR 0x200
#define RANDOM_BLOCK_MAX_SIZE 2048

#define VER_STRING "blobpak v1.3 by skgleba"

typedef struct entry_t {
    uint8_t entryID[ENC_ENTRY_ID_SIZE];
    uint32_t enc_size;
    uint64_t noise64;
} __attribute__((packed)) entry_t;

// NOTE: enc_size and noise64 MUST be at the same offset as in entry_t
// NOTE2: MUST be the same size as entry_t
typedef struct enc_entry_t {
    uint8_t iv[16];
    union {
        uint8_t toc_enc[16];
        struct {
            uint32_t hash_partial;
            uint32_t enc_size;
            uint64_t noise64;
        } toc_dec;
    };
} __attribute__((packed)) enc_entry_t;

enum OP_MODES {
    OUPUT_FILE,
    OUPUT_STDOUT,
    OUPUT_NICE,
    IPUT_FILE,
    IPUT_STDIN
};

#endif