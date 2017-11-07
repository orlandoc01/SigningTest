package com.orlando;

import java.security.*;

public class Crypto {
  public static boolean verifySignature(PublicKey pubKey, byte[] message, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    final Signature sig = Signature.getInstance("SHA256withECDSA");
    sig.initVerify(pubKey);
    sig.update(message);
    return sig.verify(signature);
  }

  public static byte[] signData(PrivateKey privateKey, byte[] message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    Signature sig = Signature.getInstance("SHA256withECDSA");
    sig.initSign(privateKey);
    sig.update(message);
    return sig.sign();
  }

  public static byte[] getChallenge() throws NoSuchAlgorithmException {
    byte[] initChallenge = new byte[20];
    SecureRandom.getInstanceStrong().nextBytes(initChallenge);
    return initChallenge;
  }

  public static KeyPair getKeyPair() throws NoSuchAlgorithmException {
    final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(256, SecureRandom.getInstanceStrong());
    return generator.generateKeyPair();
  }
}
