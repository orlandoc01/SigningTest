package com.orlando;

import java.security.*;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
	// write your code here
        final KeyPair exampleKeyPair = Crypto.getKeyPair();
        final PublicKey pubKey = exampleKeyPair.getPublic();
        final PrivateKey privKey = exampleKeyPair.getPrivate();
        final byte[] challenge = Crypto.getChallenge();
        final byte[] signature = Crypto.signData(privKey, challenge);
        final boolean isValid = Crypto.verifySignature(pubKey, challenge, signature);

        System.out.println("Heres the Public Key: ".concat(bytesToHex(pubKey.getEncoded())));
        System.out.println("Here's the Private Key: ".concat(bytesToHex(privKey.getEncoded())));
        System.out.println("Heres the challenge: ".concat(bytesToHex(challenge)));
        System.out.println("Heres the Signature: ".concat(bytesToHex(signature)));
        System.out.println("Is the Signature Valid: ".concat(String.valueOf(isValid)));
        System.out.println("");

    /* The current Crypto class creates an secp256r1 key pair. To register this as a URN on our server, we convert the raw public
    key to a hex string (which was done above), we remove the first 54 hex characters because it will always be the same across
    all secp256r1 public keys so it's not necessary to store, we ensure the string has all lowercase letters, and then we prefix the string
    with 'pbk:ec:secp256r1:04' to designate it as an secp256r1 public key URN that is uncompresssed */
        System.out.println("Heres the Public Key as a Chronicled URN -  pbk:ec:secp256r1:04".concat(bytesToHex(pubKey.getEncoded()).substring(54).toLowerCase()));

        while (true) {
            Scanner scanner = new Scanner( System.in );
            System.out.print( "Type the challenge : " );
            String input = scanner.nextLine();
            byte[] challengeAsk = hexStringToByteArray(input);
            byte[] signatureAnswer = Crypto.signData(privKey, challengeAsk);
            System.out.print( "Here's the signature:" );
            System.out.println(bytesToHex(signatureAnswer));
        }
    }

    public static String bytesToHex(byte[] bytes) {
        final char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
              + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
