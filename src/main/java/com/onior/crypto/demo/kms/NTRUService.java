package com.onior.crypto.demo.kms;

import com.onior.crypto.demo.models.application.ApplicationSession;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.pqc.crypto.ntru.*;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.stereotype.Service;

import java.io.IOException;

/**
 * Service providing basic NTRU cryptographic methods
 */
@Service
public class NTRUService {

    private NTRUEncryptionKeyPairGenerator ntruEncryptionKeyPairGenerator;
    private NTRUEncryptionKeyGenerationParameters ntruEncryptionKeyGenerationParameters;

    public NTRUService() {
        ntruEncryptionKeyPairGenerator = new NTRUEncryptionKeyPairGenerator();
        ntruEncryptionKeyGenerationParameters = NTRUEncryptionKeyGenerationParameters.APR2011_743;
        ntruEncryptionKeyPairGenerator.init(ntruEncryptionKeyGenerationParameters);
    }

    /**
     * Fills the {@link ApplicationSession} with a new keypair
     * @param session The {@link ApplicationSession} to fill
     * @return The filled {@link ApplicationSession}
     */
    public ApplicationSession fillSession(ApplicationSession session) {
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = ntruEncryptionKeyPairGenerator.generateKeyPair();
        session.setPrivateKeyServer(toBase64((NTRUEncryptionPrivateKeyParameters) asymmetricCipherKeyPair.getPrivate()));
        session.setPublicKeyServer(toBase64((NTRUEncryptionPublicKeyParameters) asymmetricCipherKeyPair.getPublic()));
        return session;
    }

    /**
     * Decrypts a Base64 encoded {@link String} based on the Base64 encoded {@link NTRUEncryptionPrivateKeyParameters}
     * @param ciphertext The {@link String} ciphertext
     * @param privateKeyString The Base64 encoded {@link NTRUEncryptionPrivateKeyParameters}
     * @return The decrypted {@link String}
     * @throws IOException When the input is malformed
     * @throws InvalidCipherTextException When the given ciphertext is invalid
     */
    public String decrypt(String ciphertext, String privateKeyString) throws IOException, InvalidCipherTextException {

        NTRUEngine ntru = new NTRUEngine();
        NTRUEncryptionPrivateKeyParameters privateKey = restorePrivateKey(privateKeyString);
        ntru.init(false, privateKey);

        byte[] ciphertextBytes = Base64.decode(ciphertext);
        return new String(ntru.processBlock(ciphertextBytes, 0, ciphertextBytes.length), "UTF-8");
    }

    /**
     * Encrypts a {@link String} based on the Base64 encoded {@link NTRUEncryptionPublicKeyParameters}
     * @param plaintext The {@link String} text
     * @param publicKeyString The Base64 encoded {@link NTRUEncryptionPublicKeyParameters}
     * @return The decrypted {@link String}
     * @throws InvalidCipherTextException When the given ciphertext is invalid
     */
    public String encrypt(String plaintext, String publicKeyString) throws InvalidCipherTextException {

        NTRUEngine ntru = new NTRUEngine();
        NTRUEncryptionPublicKeyParameters publicKey = restorePublicKey(publicKeyString);
        ntru.init(true, publicKey);

        byte[] plaintextBytes = plaintext.getBytes();
        return Base64.toBase64String(ntru.processBlock(plaintextBytes, 0, plaintextBytes.length));
    }

    /**
     * Reconstruct the {@link NTRUEncryptionPublicKeyParameters} from a Base64 encoded {@link String}
     * @param keyString The Base64 encoded {@link String}
     * @return The {@link NTRUEncryptionPublicKeyParameters}
     */
    private NTRUEncryptionPublicKeyParameters restorePublicKey(String keyString) {
        return new NTRUEncryptionPublicKeyParameters(Base64.decode(keyString), ntruEncryptionKeyGenerationParameters.getEncryptionParameters());
    }

    /**
     * Reconstruct the {@link NTRUEncryptionPrivateKeyParameters} from a Base64 encoded {@link String}
     * @param keyString The Base64 encoded {@link String}
     * @return The {@link NTRUEncryptionPrivateKeyParameters}
     */
    private NTRUEncryptionPrivateKeyParameters restorePrivateKey(String keyString) throws IOException {
        return new NTRUEncryptionPrivateKeyParameters(Base64.decode(keyString), ntruEncryptionKeyGenerationParameters.getEncryptionParameters());
    }

    /**
     * Encodes a {@link NTRUEncryptionPublicKeyParameters} to a Base64 {@link String}
     * @param publicKey The {@link NTRUEncryptionPublicKeyParameters} to encode
     * @return Teh {@link String} representation
     */
    private String toBase64(NTRUEncryptionPublicKeyParameters publicKey) {
        return Base64.toBase64String(publicKey.getEncoded());
    }

    /**
     * Encodes a {@link NTRUEncryptionPrivateKeyParameters} to a Base64 {@link String}
     * @param privateKey The {@link NTRUEncryptionPrivateKeyParameters} to encode
     * @return Teh {@link String} representation
     */
    private String toBase64(NTRUEncryptionPrivateKeyParameters privateKey) {
        return Base64.toBase64String(privateKey.getEncoded());
    }
}
