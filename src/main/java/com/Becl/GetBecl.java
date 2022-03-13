package com.Becl;


import com.ByteCodeEvil;
import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.bcel.internal.classfile.JavaClass;
import com.sun.org.apache.bcel.internal.classfile.Utility;

import java.io.IOException;

public class GetBecl {
    public static void main(String[] args) throws IOException {
        JavaClass cls = Repository.lookupClass(ByteCodeEvil.class);
        String code = Utility.encode(cls.getBytes(),true);
        System.out.println(code);
    }
}
