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
import java.security.spec.X509EncodedKeySpec;

@Service
public class RSAService {

    private final int keySize = 2048;
    private final String cipherType = "RSA";
    private KeyPairGenerator keyPairGenerator;

    public RSAService() throws NoSuchAlgorithmException {
        keyPairGenerator = KeyPairGenerator.getInstance(cipherType);
        keyPairGenerator.initialize(keySize);
    }

    public ClientSession fillSession(ClientSession session) {
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        session.setPrivateKey(toBase64(keyPair.getPrivate()));
        session.setPublicKey(toBase64(keyPair.getPublic()));
        return session;
    }

    public String decrypt(String ciphertext, String privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] response = Base64.decode(ciphertext);
        Cipher cipher = Cipher.getInstance(cipherType);
        PrivateKey decodedPrivateKey = recoverPrivateKey(privateKey);
        cipher.init(Cipher.DECRYPT_MODE, decodedPrivateKey);
        return new String(cipher.doFinal(response));
    }

    private String toBase64(PublicKey publicKey) {
        return Base64.toBase64String(publicKey.getEncoded());
    }

    private String toBase64(PrivateKey privateKey) {
        return Base64.toBase64String(privateKey.getEncoded());
    }

    private PrivateKey recoverPrivateKey(String keyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance(cipherType).generatePrivate(new X509EncodedKeySpec(Base64.decode(keyString)));
    }
}
