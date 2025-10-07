# Symmetric Cryptography Algorithms

This repository is intended for students to implement and test different symmetric cryptography algorithms.

## Implemented Algorithms

Currently, the following algorithms are implemented:

*   **AES (Advanced Encryption Standard):** A widely used symmetric encryption algorithm.
*   **XOR Cipher:** A simple symmetric cipher based on the XOR operation.

## Compiling the Project

To compile the project, you can use the `javac` compiler. Make sure you have a JDK (Java Development Kit) installed.

From the root directory of the project, run the following command:

```bash
javac -d out/production/criptografia_simetrica src/Main.java src/Test.java src/crypto/SymetricCypher.java src/crypto/algorithms/AESCipher.java src/crypto/algorithms/XORCipher.java src/io/FileIO.java
```

This will compile all the Java source files and place the compiled `.class` files in the `out/production/criptografia_simetrica` directory.
