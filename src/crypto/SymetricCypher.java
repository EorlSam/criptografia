package crypto;

import crypto.algorithms.AESCipher;
import crypto.algorithms.XORCipher;

/**
 * Main Symmetric Cipher class
 * Provides a unified interface for different encryption algorithms
 */
public class SymetricCypher {
    
    // Algorithm instances
    private final AESCipher aesCipher;
    private final XORCipher xorCipher;
    
    /**
     * Constructor - Initialize algorithm instances
     */
    public SymetricCypher() {
        this.aesCipher = new AESCipher();
        this.xorCipher = new XORCipher();
    }
    
    /**
     * Encrypt plaintext using the current algorithm (AES)
     * @param plainText The text to encrypt
     * @param key The encryption key
     * @return Encrypted result
     */
    public String encrypt(String plainText, String key) {
        return aesCipher.process(plainText, key);
    }

    /**
     * Decrypt ciphertext using the current algorithm (AES)
     * @param cypherText The text to decrypt
     * @param key The decryption key
     * @return Decrypted result
     */
    public String decrypt(String cypherText, String key) {
        return aesCipher.process(cypherText, key);
    }
    
    /**
     * Encrypt/decrypt using XOR algorithm (for testing/comparison)
     * @param text The text to process
     * @param key The key to use
     * @return Processed result
     */
    public String processWithXOR(String text, String key) {
        return xorCipher.process(text, key);
    }
    
    /**
     * Encrypt/decrypt using AES algorithm
     * @param text The text to process
     * @param key The key to use
     * @return Processed result
     */
    public String processWithAES(String text, String key) {
        return aesCipher.process(text, key);
    }
}