package com.onior.crypto.demo.kms;

import org.bouncycastle.util.encoders.Base64;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;

@Service
public class AESService {

    private final String cipherType = "AES/CBC/PKCS7Padding";
    private final String keyType = "PBKDF2WithHmacSHA512";
    private final String keySpecType = "AES";
    private final int keySize = 256;
    private final int keyIterations = 65536;
    private final byte[] staticSalt = "STATIC SALT".getBytes();

    public String expandKey(String passphrase) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(keyType);

        KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), staticSalt, keyIterations, keySize);
        SecretKey tmp = factory.generateSecret(spec);

        return toBase64(new SecretKeySpec(tmp.getEncoded(), keySpecType));
    }

    public String encrypt(String plaintext, String sessionKey) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, InvalidParameterSpecException, UnsupportedEncodingException, BadPaddingException,
            IllegalBlockSizeException {

        SecretKey key = fromBase64(sessionKey);

        Cipher cipher = Cipher.getInstance(cipherType);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] iv = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));

        return Base64.toBase64String(iv) + ":" + Base64.toBase64String(ciphertext);
    }

    public String decrypt(String ciphertext, String sessionKey) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {

        SecretKey key = fromBase64(sessionKey);
        // ciphertext is build as <iv>:<encrypted message>
        String[] ciphertextParts = ciphertext.split(":");

        if (ciphertextParts.length != 2) throw new IllegalArgumentException("Illegal ciphertext!");
        Cipher cipher = Cipher.getInstance(cipherType);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(Base64.decode(ciphertextParts[0])));

        return new String(cipher.doFinal(Base64.decode(ciphertextParts[1])));
    }

    private String toBase64(SecretKey secretKey) {
        return Base64.toBase64String(secretKey.getEncoded());
    }

    private SecretKey fromBase64(String keyString) {
        return new SecretKeySpec(Base64.decode(keyString), keySpecType);
    }
}
