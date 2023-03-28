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
#define RANDOM_BLOCK_MAX_SIZE 0x600

#define VER_STRING "blobpak v1.2 by skgleba"

typedef struct entry_t {
    unsigned char entryID[ENC_ENTRY_ID_SIZE];
    uint32_t enc_size;
    uint64_t noise64;
} __attribute__((packed)) entry_t;

enum OP_MODES {
    OUPUT_FILE,
    OUPUT_STDOUT,
    OUPUT_NICE,
    IPUT_FILE,
    IPUT_STDIN
};

#endif