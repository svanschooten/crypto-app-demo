package com.onior.crypto.demo.kms;

import com.onior.crypto.demo.models.client.ClientSession;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Service providing basic RSA cryptographic methods
 */
@Service
public class RSAService {

    private final int keySize = 3072;
    private final String cipherType = "RSA";
    private KeyPairGenerator keyPairGenerator;

    public RSAService() throws NoSuchAlgorithmException {
        keyPairGenerator = KeyPairGenerator.getInstance(cipherType);
        keyPairGenerator.initialize(keySize);
    }

    /**
     * Fills the {@link ClientSession} with a new keypair
     * @param session The {@link ClientSession} to fill
     * @return The filled {@link ClientSession}
     */
    public ClientSession fillSession(ClientSession session) {
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        session.setPrivateKey(toBase64(keyPair.getPrivate()));
        session.setPublicKey(toBase64(keyPair.getPublic()));
        return session;
    }

    /**
     * Decrypts a Base64 encoded {@link String} based on the Base64 encoded {@link PrivateKey}
     * @param ciphertext The {@link String} ciphertext
     * @param privateKey The Base64 encoded {@link PrivateKey}
     * @return The decrypted {@link String}
     * @throws BadPaddingException When the padding is invalid
     * @throws NoSuchPaddingException When the given type of padding is not found by the security provider
     * @throws NoSuchAlgorithmException When the algorithm is not found by the security provider
     * @throws InvalidKeySpecException When the keys do not match the given {@link java.security.spec.KeySpec}
     * @throws InvalidKeyException When the keys do not match
     * @throws IllegalBlockSizeException When the block size is not compatible
     */
    public String decrypt(String ciphertext, String privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] response = Base64.decode(ciphertext);
        Cipher cipher = Cipher.getInstance(cipherType);
        PrivateKey decodedPrivateKey = recoverPrivateKey(privateKey);
        cipher.init(Cipher.DECRYPT_MODE, decodedPrivateKey);
        return new String(cipher.doFinal(response));
    }

    /**
     * Encodes the {@link PublicKey} to Base64
     * @param publicKey The {@link PublicKey} to encode
     * @return The {@link String} representation of the {@link PublicKey}
     */
    private String toBase64(PublicKey publicKey) {
        return Base64.toBase64String(publicKey.getEncoded());
    }

    /**
     * Encodes the {@link PrivateKey} to Base64
     * @param privateKey The {@link PrivateKey} to encode
     * @return The {@link String} representation of the {@link PrivateKey}
     */
    private String toBase64(PrivateKey privateKey) {
        return Base64.toBase64String(privateKey.getEncoded());
    }

    /**
     * Reconstruct the {@link PrivateKey} from the Base64 {@link String} representation
     * @param keyString The Base64 {@link String} representation
     * @return The {@link PrivateKey}
     * @throws NoSuchAlgorithmException When the algorithm is not found by the security provider
     * @throws InvalidKeySpecException When the keys do not match the given {@link java.security.spec.KeySpec}
     */
    private PrivateKey recoverPrivateKey(String keyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance(cipherType).generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(keyString)));
    }
}
