import java.security.KeyPairGenerator;
class Keys { void f() throws Exception {
  KeyPairGenerator k=KeyPairGenerator.getInstance("RSA"); k.initialize(1024);
}}