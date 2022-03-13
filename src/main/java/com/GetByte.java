package com;

import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.NotFoundException;

import java.io.IOException;
import java.util.Base64;

public class GetByte {
    public static void main(String[] args) throws NotFoundException, IOException, CannotCompileException {
        ClassPool pool = ClassPool.getDefault();
        CtClass clazz = pool.get(ByteCodeEvil.class.getName());
        byte[] code = clazz.toBytecode();
        String bytes = Base64.getEncoder().encodeToString(code);
//        String code = Utility.encode(clazz.toBytecode(),true);
        System.out.println(bytes);
    }
}
