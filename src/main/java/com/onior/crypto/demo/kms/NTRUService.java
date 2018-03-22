package com.onior.crypto.demo.kms;

import com.onior.crypto.demo.models.application.ApplicationSession;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.pqc.crypto.ntru.*;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class NTRUService {

    private NTRUEncryptionKeyPairGenerator ntruEncryptionKeyPairGenerator;
    private NTRUEncryptionKeyGenerationParameters ntruEncryptionKeyGenerationParameters;

    public NTRUService() {
        ntruEncryptionKeyPairGenerator = new NTRUEncryptionKeyPairGenerator();
        ntruEncryptionKeyGenerationParameters = NTRUEncryptionKeyGenerationParameters.APR2011_743;
        ntruEncryptionKeyPairGenerator.init(ntruEncryptionKeyGenerationParameters);
    }

    public ApplicationSession fillSession(ApplicationSession session) {
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = ntruEncryptionKeyPairGenerator.generateKeyPair();
        session.setPrivateKeyServer(toBase64((NTRUEncryptionPrivateKeyParameters) asymmetricCipherKeyPair.getPrivate()));
        session.setPublicKeyServer(toBase64((NTRUEncryptionPublicKeyParameters) asymmetricCipherKeyPair.getPublic()));
        return session;
    }

    public String decrypt(String ciphertext, String privateKeyString) throws IOException, InvalidCipherTextException {

        NTRUEngine ntru = new NTRUEngine();
        NTRUEncryptionPrivateKeyParameters privateKey = restorePrivateKey(privateKeyString);
        ntru.init(false, privateKey);

        byte[] ciphertextBytes = Base64.decode(ciphertext);
        return new String(ntru.processBlock(ciphertextBytes, 0, ciphertextBytes.length), "UTF-8");
    }

    public String encrypt(String plaintext, String publicKeyString) throws InvalidCipherTextException {

        NTRUEngine ntru = new NTRUEngine();
        NTRUEncryptionPublicKeyParameters publicKey = restorePublicKey(publicKeyString);
        ntru.init(true, publicKey);

        byte[] plaintextBytes = plaintext.getBytes();
        return Base64.toBase64String(ntru.processBlock(plaintextBytes, 0, plaintextBytes.length));
    }

    private NTRUEncryptionPublicKeyParameters restorePublicKey(String keyString) {
        return new NTRUEncryptionPublicKeyParameters(Base64.decode(keyString), ntruEncryptionKeyGenerationParameters.getEncryptionParameters());
    }

    private NTRUEncryptionPrivateKeyParameters restorePrivateKey(String keyString) throws IOException {
        return new NTRUEncryptionPrivateKeyParameters(Base64.decode(keyString), ntruEncryptionKeyGenerationParameters.getEncryptionParameters());
    }

    private String toBase64(NTRUEncryptionPublicKeyParameters publicKey) {
        return Base64.toBase64String(publicKey.getEncoded());
    }

    private String toBase64(NTRUEncryptionPrivateKeyParameters privateKey) {
        return Base64.toBase64String(privateKey.getEncoded());
    }
}
