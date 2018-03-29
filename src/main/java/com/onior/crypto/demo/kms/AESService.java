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

/**
 * Service providing basic AES cryptographic methods
 */
@Service
public class AESService {

    private final String cipherType = "AES/CBC/PKCS7Padding";
    private final String keyType = "PBKDF2WithHmacSHA512";
    private final String keySpecType = "AES";
    private final int keySize = 256;
    private final int keyIterations = 4096;
    private final byte[] staticSalt = "DOCULAYER STATIC SALT".getBytes();

    /**
     * Expands a key based on a passphrase with the PBKDF2WithHmacSHA512 algorithm and 4096 iterations.
     * Creates a Base64 encoded {@link SecretKey} of length 256.
     * @param passphrase The {@link String} to use as input
     * @return The Base64 encoded {@link SecretKey}
     * @throws NoSuchAlgorithmException When the algorithm is not found by the security provider
     * @throws InvalidKeySpecException When the keys do not match the given {@link java.security.spec.KeySpec}
     */
    public String expandKey(String passphrase) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(keyType);

        KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), staticSalt, keyIterations, keySize);
        SecretKey tmp = factory.generateSecret(spec);

        return toBase64(new SecretKeySpec(tmp.getEncoded(), keySpecType));
    }

    /**
     * Generates a new randomly generated, Base64 encode, {@link SecretKey}
     * @return The Base64 encoded {@link SecretKey}
     * @throws NoSuchAlgorithmException When the algorithm is not found by the security provider
     */
    public String generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(keySpecType);
        keyGenerator.init(keySize);
        return toBase64(keyGenerator.generateKey());
    }

    /**
     * Encrypts a {@link String} based on the Base64 encoded {@link SecretKey}
     * @param plaintext The {@link String} to encrypt
     * @param sessionKey The Base64 encoded {@link SecretKey}
     * @return The encrypted {@link String}
     * @throws NoSuchPaddingException When the given type of padding is not found by the security provider
     * @throws NoSuchAlgorithmException When the algorithm is not found by the security provider
     * @throws InvalidKeyException When the keys do not match
     * @throws InvalidParameterSpecException When the given parameter specification is invalid
     * @throws UnsupportedEncodingException When the encoding is not supported
     * @throws BadPaddingException When the padding is invalid
     * @throws IllegalBlockSizeException When the block size is not compatible
     */
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

    /**
     * Decrypts a Base64 encoded {@link String} based on the Base64 encoded {@link SecretKey}
     * @param ciphertext The Base64 encoded {@link String} to decrypt
     * @param sessionKey The Base64 encoded {@link SecretKey}
     * @return The decrypted {@link String}
     * @throws NoSuchPaddingException When the given type of padding is not found by the security provider
     * @throws NoSuchAlgorithmException When the algorithm is not found by the security provider
     * @throws InvalidKeyException When the keys do not match
     * @throws InvalidAlgorithmParameterException When a key parameter is not correct
     * @throws BadPaddingException When the padding is invalid
     * @throws IllegalBlockSizeException When the block size is not compatible
     */
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

    /**
     * Encodes a {@link SecretKey} in Base64
     * @param secretKey The {@link SecretKey} to encode
     * @return The {@link String} representation in Base64
     */
    private String toBase64(SecretKey secretKey) {
        return Base64.toBase64String(secretKey.getEncoded());
    }

    /**
     * Reconstructs the {@link SecretKey} from the Base64 encoded {@link String} representation
     * @param keyString The {@link String} representation
     * @return The {@link SecretKey}
     */
    private SecretKey fromBase64(String keyString) {
        return new SecretKeySpec(Base64.decode(keyString), keySpecType);
    }
}
