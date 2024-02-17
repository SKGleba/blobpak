/*
 * Copyright (C) 2022-2024 skgleba
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifndef __BLOBPAK_H__
#define __BLOBPAK_H__

#define ENC_ENTRY_ID_SIZE 20        // SHA-1 hash size
#define DEC_ENTRY_ID_SIZE 128       // Truncated name size
#define STDIN_BUF_INCR 0x200        // Block size for reading from stdin
#define RANDOM_BLOCK_MAX_SIZE 2048  // Maximum size of a random padding block

#define VER_STRING "blobpak v1.3 by skgleba"

/**
 * @brief Structure representing an entry in the blobpak.
 */
typedef struct entry_t {
    uint8_t entryID[ENC_ENTRY_ID_SIZE]; /**< The (hashed) ID of the entry. */
    uint32_t enc_size;                  /**< The (hashed) size of the entry. */
    uint64_t noise64;                   /**< The noise value used for hashing. */
} __attribute__((packed)) entry_t;

/**
 * @brief Encrypted structure representing an entry in the blobpak.
 *
 * @note The enc_size and noise64 fields must be at the same offset as in the entry_t structure.
 * @note The size of this structure must be the same as the entry_t structure.
 */
typedef struct enc_entry_t {
    uint8_t iv[16]; /**< The IV used for encryption. */
    union {
        uint8_t toc_enc[16];
        struct {
            uint32_t hash_partial; /**< partial of the hashed name, used for validation. */
            uint32_t enc_size;     /**< The (hashed) size of the entry. */
            uint64_t noise64;      /**< The noise value used for hashing. */
        } toc_dec;
    };
} __attribute__((packed)) enc_entry_t;

enum OP_MODES { OUPUT_FILE, OUPUT_STDOUT, OUPUT_NICE, IPUT_FILE, IPUT_STDIN };

#endif