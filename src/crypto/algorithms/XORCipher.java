package crypto.algorithms;

import java.nio.charset.StandardCharsets;

/**
 * XOR Cipher implementation
 * Simple symmetric cipher using XOR operations with key repetition
 */
public class XORCipher {
    
    /**
     * Encrypt or decrypt text using XOR cipher
     * @param text The text to encrypt/decrypt
     * @param key The encryption key
     * @return Encrypted/decrypted result
     */
    public String process(String text, String key) {
        // Check if this is encrypted data (numbers separated by spaces) or plain text
        // Encrypted data has spaces separating numbers
        if (text.matches("^[0-9 ]+$") && text.contains(" ")) {
            // This is encrypted data - decrypt it
            return decrypt(text, key);
        } else {
            // This is plain text - encrypt it
            return encrypt(text, key);
        }
    }
    
    /**
     * Encrypt plaintext using XOR
     */
    private String encrypt(String plaintext, String key) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < plaintext.length(); i++) {
            char c = plaintext.charAt(i);
            char k = key.charAt(i % key.length());
            int xorResult = c ^ k;
            sb.append(xorResult).append(" ");
        }
        return sb.toString();
    }
    
    /**
     * Decrypt ciphertext using XOR
     */
    private String decrypt(String ciphertext, String key) {
        String[] numbers = ciphertext.split(" ");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < numbers.length; i++) {
            int encryptedValue = Integer.parseInt(numbers[i]);
            char k = key.charAt(i % key.length());
            char originalChar = (char)(encryptedValue ^ k);
            sb.append(originalChar);
        }
        return sb.toString();
    }
}