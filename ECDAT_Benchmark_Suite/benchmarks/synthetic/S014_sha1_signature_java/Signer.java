import java.security.Signature;
public class Signer {
  Signature s() throws Exception { return Signature.getInstance("SHA1withRSA"); }
}