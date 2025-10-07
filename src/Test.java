import crypto.SymetricCypher;

/**
 * Comprehensive test for the refactored symmetric cipher
 * Tests both XOR and AES algorithms with various inputs
 */
public class Test {
    
    public static void main(String[] args) {
        System.out.println("=== Symmetric Cipher Test Suite ===");
        System.out.println("Testing refactored algorithms...\n");
        
        SymetricCypher cipher = new SymetricCypher();
        
        // Test cases
        testXORAlgorithm(cipher);
        testAESAlgorithm(cipher);
        testEdgeCases(cipher);
        
        System.out.println("=== All Tests Completed ===");
    }
    
    /**
     * Test XOR algorithm with various inputs
     */
    private static void testXORAlgorithm(SymetricCypher cipher) {
        System.out.println("--- XOR Algorithm Tests ---");
        
        // Test 1: Basic text
        testXOR(cipher, "Hello World!", "key123", "Test 1 - Basic text");
        
        // Test 2: Empty string
        testXOR(cipher, "", "key", "Test 2 - Empty string");
        
        // Test 3: Single character
        testXOR(cipher, "A", "x", "Test 3 - Single character");
        
        // Test 4: Numbers and symbols
        testXOR(cipher, "123!@#ABC", "mykey", "Test 4 - Numbers and symbols");
        
        // Test 5: Long key
        testXOR(cipher, "short", "verylongkeyhere", "Test 5 - Long key");
        
        // Test 6: Long text
        testXOR(cipher, "This is a much longer text to test the XOR algorithm with multiple characters and spaces.", "secretkey", "Test 6 - Long text");
        
        System.out.println();
    }
    
    /**
     * Test AES algorithm with various inputs
     */
    private static void testAESAlgorithm(SymetricCypher cipher) {
        System.out.println("--- AES Algorithm Tests ---");
        
        // Test 1: Basic text
        testAES(cipher, "Hello World!", "1234567890123456", "Test 1 - Basic text (16-byte key)");
        
        // Test 2: Short key (will be padded)
        testAES(cipher, "Hello World!", "short", "Test 2 - Short key (auto-padding)");
        
        // Test 3: Exact block size
        testAES(cipher, "1234567890123456", "myverysecretkey1", "Test 3 - Exact block size");
        
        // Test 4: Multiple blocks
        testAES(cipher, "This is a longer message that will span multiple AES blocks for testing purposes.", "supersecretkey16", "Test 4 - Multiple blocks");
        
        // Test 5: Special characters
        testAES(cipher, "Héllo Wörld! 🌟", "testkey123456789", "Test 5 - Special characters");
        
        // Test 6: Numbers and symbols
        testAES(cipher, "Test123!@#$%^&*()", "anotherkey123456", "Test 6 - Numbers and symbols");
        
        System.out.println();
    }
    
    /**
     * Test edge cases and error conditions
     */
    private static void testEdgeCases(SymetricCypher cipher) {
        System.out.println("--- Edge Cases Tests ---");
        
        try {
            // Test facade methods
            String text = "Test facade methods";
            String key = "testkey";
            
            System.out.println("Testing facade encrypt/decrypt methods:");
            String encrypted = cipher.encrypt(text, key);
            String decrypted = cipher.decrypt(encrypted, key);
            
            System.out.println("Original: " + text);
            System.out.println("Encrypted: " + encrypted);
            System.out.println("Decrypted: " + decrypted);
            System.out.println("Success: " + text.equals(decrypted));
            System.out.println();
            
            // Test direct method calls
            System.out.println("Testing direct method calls:");
            String aesResult = cipher.processWithAES("Direct AES test", "directkey123456");
            String aesBack = cipher.processWithAES(aesResult, "directkey123456");
            System.out.println("AES direct test success: " + "Direct AES test".equals(aesBack));
            
            String xorResult = cipher.processWithXOR("Direct XOR test", "directkey");
            String xorBack = cipher.processWithXOR(xorResult, "directkey");
            System.out.println("XOR direct test success: " + "Direct XOR test".equals(xorBack));
            
        } catch (Exception e) {
            System.out.println("Error in edge cases: " + e.getMessage());
            e.printStackTrace();
        }
        
        System.out.println();
    }
    
    /**
     * Helper method to test XOR encryption/decryption
     */
    private static void testXOR(SymetricCypher cipher, String text, String key, String testName) {
        try {
            String encrypted = cipher.processWithXOR(text, key);
            String decrypted = cipher.processWithXOR(encrypted, key);
            boolean success = text.equals(decrypted);
            
            System.out.println(testName + ": " + (success ? "✓ PASS" : "✗ FAIL"));
            if (!success) {
                System.out.println("  Original: '" + text + "'");
                System.out.println("  Decrypted: '" + decrypted + "'");
            }
        } catch (Exception e) {
            System.out.println(testName + ": ✗ FAIL (Exception: " + e.getMessage() + ")");
        }
    }
    
    /**
     * Helper method to test AES encryption/decryption
     */
    private static void testAES(SymetricCypher cipher, String text, String key, String testName) {
        try {
            String encrypted = cipher.processWithAES(text, key);
            String decrypted = cipher.processWithAES(encrypted, key);
            boolean success = text.equals(decrypted);
            
            System.out.println(testName + ": " + (success ? "✓ PASS" : "✗ FAIL"));
            if (!success) {
                System.out.println("  Original: '" + text + "'");
                System.out.println("  Decrypted: '" + decrypted + "'");
            }
        } catch (Exception e) {
            System.out.println(testName + ": ✗ FAIL (Exception: " + e.getMessage() + ")");
        }
    }
}