import crypto.*;
import io.FileIO;

import javax.net.ssl.KeyManager;

public class Main {
    public static void main(String[] args) throws Exception {
        String filePath = args[0];
        String key = args[1];

        SymetricCypher cypher = new SymetricCypher();
        String content = FileIO.read(filePath);
        String result;
        String outputPath;

        if (filePath.endsWith(".enc")) {
            result = cypher.decrypt(content, key);
            outputPath = "decrypted_" + filePath.substring(0, filePath.length() - 4);
            System.out.println("Decriptando el fichero...");
        } else {
            result = cypher.encrypt(content, key);
            outputPath = filePath + ".enc";
            System.out.println("Encriptando el fichero...");
        }

        FileIO.write(outputPath, result);
        System.out.println("Operación completada correctamente.");
    }
}