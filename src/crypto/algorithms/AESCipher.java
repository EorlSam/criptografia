package crypto.algorithms;

import java.nio.charset.StandardCharsets;

/**
 * AES Cipher implementation
 * Advanced Encryption Standard (AES-128) implementation from scratch
 */
public class AESCipher {

    // AES S-Box for SubBytes transformation
    private static final int[] SBOX = {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    // Round constants for key schedule
    private static final int[] RCON = {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    // Inverse S-Box for decryption
    private static final int[] INV_SBOX = {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    /**
     * Main method for AES encryption/decryption
     *
     * @param text The text to process
     * @param key  The encryption key
     * @return Processed result
     */
    public String process(String text, String key) {
        int rounds = 10; // default for AES-128
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        int keyBitLength = keyBytes.length * 8;

        if (keyBitLength == 128) rounds = 10;
        else if (keyBitLength == 192) rounds = 12;
        else if (keyBitLength == 256) rounds = 14;
        else {
            // Pad or truncate key to 128 bits for now
            byte[] paddedKey = new byte[16];
            System.arraycopy(keyBytes, 0, paddedKey, 0, Math.min(keyBytes.length, 16));
            keyBytes = paddedKey;
            rounds = 10;
        }

        // Generate round keys using key schedule
        int[][] roundKeys = keySchedule(keyBytes, rounds);

        // Determine if this is encryption or decryption based on content
        // Encrypted data has spaces separating numbers and typically many more numbers
        if (text.matches("^[0-9 ]+$") && text.contains(" ") && text.split(" ").length >= 16) {
            // This looks like encrypted data (space-separated numbers) - decrypt it
            return aesDecrypt(text, roundKeys, rounds);
        } else {
            // This is plain text - encrypt it
            return aesEncrypt(text, roundKeys, rounds);
        }
    }


    /**
     * AES Encryption
     */
    private String aesEncrypt(String plaintext, int[][] roundKeys, int rounds) {
        byte[][] blocks = textToBlocks(plaintext);
        StringBuilder result = new StringBuilder();

        for (int blockIndex = 0; blockIndex < blocks.length; blockIndex++) {
            byte[] block = blocks[blockIndex];
            int[][] state = blockToState(block);

            // Initial round key addition
            addRoundKey(state, roundKeys[0]);

            // Main rounds
            for (int round = 1; round < rounds; round++) {
                subBytes(state);
                shiftRows(state);
                mixColumns(state);
                addRoundKey(state, roundKeys[round]);
            }

            // Final round (no MixColumns)
            subBytes(state);
            shiftRows(state);
            addRoundKey(state, roundKeys[rounds]);

            // Convert state back to bytes and append to result
            byte[] encryptedBlock = stateToBlock(state);
            for (int i = 0; i < encryptedBlock.length; i++) {
                if (result.length() > 0) result.append(" ");
                result.append(encryptedBlock[i] & 0xFF);
            }
        }

        return result.toString();
    }

    /**
     * AES Decryption
     */
    private String aesDecrypt(String ciphertext, int[][] roundKeys, int rounds) {
        // Parse encrypted data
        String[] numbers = ciphertext.split(" ");
        int blockCount = numbers.length / 16;
        byte[][] blocks = new byte[blockCount][16];

        // Convert numbers back to bytes
        for (int i = 0; i < numbers.length; i++) {
            int blockIndex = i / 16;
            int byteIndex = i % 16;
            blocks[blockIndex][byteIndex] = (byte) Integer.parseInt(numbers[i]);
        }

        // Decrypt each block
        for (int blockIndex = 0; blockIndex < blocks.length; blockIndex++) {
            byte[] block = blocks[blockIndex];
            int[][] state = blockToState(block);

            // Initial round key addition
            addRoundKey(state, roundKeys[rounds]);

            // Main rounds (in reverse)
            for (int round = rounds - 1; round > 0; round--) {
                invShiftRows(state);
                invSubBytes(state);
                addRoundKey(state, roundKeys[round]);
                invMixColumns(state);
            }

            // Final round (no InvMixColumns)
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, roundKeys[0]);

            // Convert state back to bytes
            blocks[blockIndex] = stateToBlock(state);
        }

        return blocksToText(blocks);
    }

    /**
     * AES Key Schedule - expands the key into round keys
     * For AES-128: generates 11 round keys (44 words total)
     * For AES-192: generates 13 round keys (52 words total)
     * For AES-256: generates 15 round keys (60 words total)
     */
    private int[][] keySchedule(byte[] key, int rounds) {
        int keyWords = key.length / 4;  // Number of 32-bit words in key
        int totalWords = 4 * (rounds + 1);  // Total words needed for all round keys

        // Initialize word array
        int[] w = new int[totalWords];

        // Copy original key as first words
        for (int i = 0; i < keyWords; i++) {
            w[i] = (key[4 * i] << 24) | ((key[4 * i + 1] & 0xFF) << 16) |
                    ((key[4 * i + 2] & 0xFF) << 8) | (key[4 * i + 3] & 0xFF);
        }

        // Generate remaining words
        for (int i = keyWords; i < totalWords; i++) {
            int temp = w[i - 1];

            if (i % keyWords == 0) {
                // Every keyWords-th word: apply RotWord, SubWord, and XOR with Rcon
                temp = subWord(rotWord(temp)) ^ (RCON[i / keyWords - 1] << 24);
            } else if (keyWords > 6 && i % keyWords == 4) {
                // For AES-256 only: apply SubWord to every 4th word after keyWords
                temp = subWord(temp);
            }

            w[i] = w[i - keyWords] ^ temp;
        }

        // Convert to 2D array of round keys
        int[][] roundKeys = new int[rounds + 1][4];
        for (int round = 0; round <= rounds; round++) {
            for (int word = 0; word < 4; word++) {
                roundKeys[round][word] = w[round * 4 + word];
            }
        }

        return roundKeys;
    }

    /**
     * RotWord - Rotate 32-bit word left by one byte
     * [A,B,C,D] -> [B,C,D,A]
     */
    private int rotWord(int word) {
        return (word << 8) | ((word >>> 24) & 0xFF);
    }

    /**
     * SubWord - Apply S-Box substitution to each byte of the word
     */
    private int subWord(int word) {
        int result = 0;
        for (int i = 0; i < 4; i++) {
            int byteVal = (word >>> (8 * (3 - i))) & 0xFF;
            result |= (SBOX[byteVal] << (8 * (3 - i)));
        }
        return result;
    }

    // State matrix operations
    private byte[][] textToBlocks(String text) {
        byte[] textBytes = text.getBytes(StandardCharsets.UTF_8);
        
        // PKCS7 padding: always add padding, even if text length is multiple of 16
        int paddingLength = 16 - (textBytes.length % 16);
        if (paddingLength == 0) paddingLength = 16; // Add full block if exactly divisible
        
        int totalLength = textBytes.length + paddingLength;
        int blockCount = totalLength / 16;
        byte[][] blocks = new byte[blockCount][16];

        // Copy original text
        for (int i = 0; i < textBytes.length; i++) {
            int blockIndex = i / 16;
            int byteIndex = i % 16;
            blocks[blockIndex][byteIndex] = textBytes[i];
        }
        
        // Add PKCS7 padding
        for (int i = textBytes.length; i < totalLength; i++) {
            int blockIndex = i / 16;
            int byteIndex = i % 16;
            blocks[blockIndex][byteIndex] = (byte) paddingLength;
        }
        
        return blocks;
    }

    private String blocksToText(byte[][] blocks) {
        if (blocks.length == 0) return "";

        int totalLength = blocks.length * 16;
        byte[] result = new byte[totalLength];

        for (int block = 0; block < blocks.length; block++) {
            System.arraycopy(blocks[block], 0, result, block * 16, 16);
        }

        int paddingLength = result[result.length - 1] & 0xFF;
        if (paddingLength > 0 && paddingLength <= 16) {
            boolean validPadding = true;
            for (int i = result.length - paddingLength; i < result.length; i++) {
                if ((result[i] & 0xFF) != paddingLength) {
                    validPadding = false;
                    break;
                }
            }
            if (validPadding) {
                byte[] unpaddedResult = new byte[result.length - paddingLength];
                System.arraycopy(result, 0, unpaddedResult, 0, unpaddedResult.length);
                result = unpaddedResult;
            }
        }
        return new String(result, StandardCharsets.UTF_8);
    }

    private int[][] blockToState(byte[] block) {
        int[][] state = new int[4][4];
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                state[row][col] = block[col * 4 + row] & 0xFF;
            }
        }
        return state;
    }

    private byte[] stateToBlock(int[][] state) {
        byte[] block = new byte[16];
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                block[col * 4 + row] = (byte) state[row][col];
            }
        }
        return block;
    }

    // AES round operations
    private void addRoundKey(int[][] state, int[] roundKey) {
        for (int col = 0; col < 4; col++) {
            int keyWord = roundKey[col];
            for (int row = 0; row < 4; row++) {
                int keyByte = (keyWord >>> (8 * (3 - row))) & 0xFF;
                state[row][col] ^= keyByte;
            }
        }
    }

    private void subBytes(int[][] state) {
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                state[row][col] = SBOX[state[row][col]];
            }
        }
    }

    private void invSubBytes(int[][] state) {
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                state[row][col] = INV_SBOX[state[row][col]];
            }
        }
    }

    private void shiftRows(int[][] state) {
        // Row 1: shift left by 1
        int temp = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = temp;

        // Row 2: shift left by 2
        int temp1 = state[2][0], temp2 = state[2][1];
        state[2][0] = state[2][2];
        state[2][1] = state[2][3];
        state[2][2] = temp1;
        state[2][3] = temp2;

        // Row 3: shift left by 3
        temp = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = temp;
    }

    private void invShiftRows(int[][] state) {
        // Row 1: shift right by 1
        int temp = state[1][3];
        state[1][3] = state[1][2];
        state[1][2] = state[1][1];
        state[1][1] = state[1][0];
        state[1][0] = temp;

        // Row 2: shift right by 2
        int temp1 = state[2][2], temp2 = state[2][3];
        state[2][2] = state[2][0];
        state[2][3] = state[2][1];
        state[2][0] = temp1;
        state[2][1] = temp2;

        // Row 3: shift right by 3
        temp = state[3][0];
        state[3][0] = state[3][1];
        state[3][1] = state[3][2];
        state[3][2] = state[3][3];
        state[3][3] = temp;
    }

    private int gmul(int a, int b) {
        int p = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) p ^= a;
            boolean highBit = (a & 0x80) != 0;
            a <<= 1;
            if (highBit) a ^= 0x1b;
            b >>= 1;
        }
        return p & 0xFF;
    }

    private void mixColumns(int[][] state) {
        for (int col = 0; col < 4; col++) {
            int s0 = state[0][col], s1 = state[1][col], s2 = state[2][col], s3 = state[3][col];
            state[0][col] = gmul(2, s0) ^ gmul(3, s1) ^ s2 ^ s3;
            state[1][col] = s0 ^ gmul(2, s1) ^ gmul(3, s2) ^ s3;
            state[2][col] = s0 ^ s1 ^ gmul(2, s2) ^ gmul(3, s3);
            state[3][col] = gmul(3, s0) ^ s1 ^ s2 ^ gmul(2, s3);
        }
    }

    private void invMixColumns(int[][] state) {
        for (int col = 0; col < 4; col++) {
            int s0 = state[0][col], s1 = state[1][col], s2 = state[2][col], s3 = state[3][col];
            state[0][col] = gmul(14, s0) ^ gmul(11, s1) ^ gmul(13, s2) ^ gmul(9, s3);
            state[1][col] = gmul(9, s0) ^ gmul(14, s1) ^ gmul(11, s2) ^ gmul(13, s3);
            state[2][col] = gmul(13, s0) ^ gmul(9, s1) ^ gmul(14, s2) ^ gmul(11, s3);
            state[3][col] = gmul(11, s0) ^ gmul(13, s1) ^ gmul(9, s2) ^ gmul(14, s3);
        }
    }
}
