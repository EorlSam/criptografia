package io;

import java.nio.file.*;
import java.nio.charset.StandardCharsets;

public class FileIO {
    public static String read(String path) throws Exception {
        byte[] fileBytes = Files.readAllBytes(Path.of(path));
        return new String(fileBytes, StandardCharsets.ISO_8859_1);
    }

    public static void write(String path, String data) throws Exception {
        Files.write(Path.of(path), data.getBytes(StandardCharsets.ISO_8859_1));
    }
}
