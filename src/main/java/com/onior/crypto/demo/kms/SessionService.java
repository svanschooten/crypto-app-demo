package com.onior.crypto.demo.kms;

import com.onior.crypto.demo.controllers.request.ApplicationIdRequest;
import com.onior.crypto.demo.controllers.request.SessionKeyRequest;
import com.onior.crypto.demo.controllers.request.SessionRefreshRequest;
import com.onior.crypto.demo.controllers.response.ApplicationSessionResponse;
import com.onior.crypto.demo.controllers.response.ClientSessionResponse;
import com.onior.crypto.demo.controllers.response.SessionRefreshResponse;
import com.onior.crypto.demo.models.Session;
import com.onior.crypto.demo.models.application.ApplicationSession;
import com.onior.crypto.demo.models.client.ClientSession;
import lombok.Getter;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.HashMap;
import java.util.UUID;
import java.util.logging.Logger;

/**
 * Service that manages {@link Session} and basic cryptographic functions.
 */
@Service
public class SessionService {

    private HashMap<String, Session> clientSessions;
    private HashMap<String, Session> applicationSessions;
    private RSAService rsaService;
    private NTRUService ntruService;
    @Getter
    private AESService aesService;
    private Logger logger = Logger.getLogger(this.getClass().getName());

    @Autowired
    public SessionService(RSAService rsaService, NTRUService ntruService, AESService aesService) {
        this.clientSessions = new HashMap<>();
        this.applicationSessions = new HashMap<>();
        this.rsaService = rsaService;
        this.ntruService = ntruService;
        this.aesService = aesService;
    }

    /**
     * Generates a random refresh token based on UUID
     * @return The {@link String} representation of the refresh token
     */
    private String generateRefreshToken() {
        return Base64.toBase64String(UUID.randomUUID().toString().getBytes());
    }

    /**
     * Inserts or updates a {@link Session}
     * @param session The {@link ClientSession} to insert or update
     */
    private void setSession(ClientSession session) {
        this.clientSessions.put(session.getSessionId(), session);
    }

    /**
     * Inserts or updates a {@link Session}
     * @param session The {@link ApplicationSession} to insert or update
     */
    private void setSession(ApplicationSession session) {
        this.applicationSessions.put(session.getSessionId(), session);
    }

    /**
     * Creates and returns a new {@link ClientSession}
     * @return The new {@link ClientSession}
     */
    private ClientSession createClientSession() {
        ClientSession session = new ClientSession();
        session = this.rsaService.fillSession(session);
        this.clientSessions.put(session.getSessionId(), session);
        return session;
    }

    /**
     * Agnostic implementation for creating a Session based on Type
     * @param type The {@link Session.Type}
     * @return The newly created {@link Session}
     */
    public Session createSession(Session.Type type) {
        if (type == Session.Type.CLIENT) {
            return createClientSession();
        } else {
            return createApplicationSession();
        }
    }

    /**
     * Returns a {@link Session} based on type and ID
     * @param sessionId The {@link Session} ID to find
     * @param type The type of {@link Session} to find
     * @return The found {@link Session}
     * @throws NullPointerException When not found
     */
    public Session getSession(String sessionId, Session.Type type) {
        Session session;
        if (type == Session.Type.CLIENT) {
            session = this.clientSessions.get(sessionId);
        } else {
            session = this.applicationSessions.get(sessionId);
        }
        if (session == null) throw new NullPointerException("Session not found");
        return session;
    }

    /**
     * Finalizes the {@link Session} that has the basic setup setup done (last part of handshake)
     * @param session The {@link Session} to finalize
     * @param sessionKeyRequest The {@link SessionKeyRequest}
     * @return {@link ClientSessionResponse} containing the encrypted refreshToken
     * @throws InvalidKeySpecException When the keys do not match the given {@link java.security.spec.KeySpec}
     * @throws NoSuchAlgorithmException When the algorithm is not found by the security provider
     * @throws IllegalBlockSizeException When the block size is not compatible
     * @throws InvalidKeyException When the keys do not match
     * @throws BadPaddingException When the padding is invalid
     * @throws NoSuchPaddingException When the given type of padding is not found by the security provider
     * @throws InvalidParameterSpecException When the given parameter specification is invalid
     * @throws UnsupportedEncodingException When the encoding is not supported
     */
    public ClientSessionResponse finalizeClientSession(ClientSession session, SessionKeyRequest sessionKeyRequest) throws
            InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, NoSuchPaddingException, InvalidParameterSpecException, UnsupportedEncodingException {
        session.setRefreshToken(this.generateRefreshToken());

        ClientSessionResponse response = ClientSessionResponse.fromClientSession(session);

        String sessionKeyPassphrase = rsaService.decrypt(sessionKeyRequest.getSessionKey(), session.getPrivateKey());
        String sessionKey = aesService.expandKey(sessionKeyPassphrase);

        session.setSessionKey(sessionKey);
        setSession(session);

        response.setRefreshToken(aesService.encrypt(response.getRefreshToken(), sessionKey));

        return response;
    }

    /**
     * Creates and returns a new {@link ApplicationSession}
     * @return The new {@link ApplicationSession}
     */
    private ApplicationSession createApplicationSession() {
        ApplicationSession session = new ApplicationSession();
        session = this.ntruService.fillSession(session);
        setSession(session);
        return session;
    }

    /**
     * Refreshes a session based on the refresh token
     * @param session The {@link Session} to refresh
     * @param sessionRefreshRequest {@link SessionRefreshRequest} containing the current session key encrypted with the expanded refresh token
     * @param type The {@link Session.Type}
     * @return {@link SessionRefreshResponse} containing the new refresh token and session key
     * @throws InvalidKeySpecException When the keys do not match the given {@link java.security.spec.KeySpec}
     * @throws NoSuchAlgorithmException When the algorithm is not found by the security provider
     * @throws IllegalBlockSizeException When the block size is not compatible
     * @throws InvalidKeyException When the keys do not match
     * @throws BadPaddingException When the padding is invalid
     * @throws NoSuchPaddingException When the given type of padding is not found by the security provider
     * @throws InvalidParameterSpecException When the given parameter specification is invalid
     * @throws UnsupportedEncodingException When the encoding is not supported
     * @throws InvalidAlgorithmParameterException When a key parameter is not correct
     */
    public SessionRefreshResponse refreshSession(Session session, SessionRefreshRequest sessionRefreshRequest, Session.Type type) throws
            InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidParameterSpecException,
            UnsupportedEncodingException {
        String refreshKey = aesService.expandKey(session.getRefreshToken());
        String receivedSessionKey = aesService.decrypt(sessionRefreshRequest.getSessionKey(), refreshKey);

        if (!receivedSessionKey.equals(session.getSessionKey())) throw new InvalidKeyException("Invalid session key!");

        String newRefreshToken = generateRefreshToken();
        String newSessionKey = aesService.generateKey();

        SessionRefreshResponse response = new SessionRefreshResponse();
        response.setRefreshToken(aesService.encrypt(newRefreshToken, refreshKey));
        response.setSessionKey(aesService.encrypt(newSessionKey, refreshKey));

        session = session.refresh(newRefreshToken, newSessionKey);
        if (type == Session.Type.CLIENT) {
            clientSessions.put(session.getSessionId(), session);
        } else {
            applicationSessions.put(session.getSessionId(), session);
        }

        return response;
    }

    /**
     * Destroys a {@link Session}
     * @param session The {@link Session} to destroy
     * @param type The {@link Session.Type}
     */
    public void destroySession(Session session, Session.Type type) {
        if (type == Session.Type.CLIENT) {
            clientSessions.remove(session.getSessionId());
        } else {
            applicationSessions.remove(session.getSessionId());
        }
    }

    /**
     * Finalizes the {@link Session} that has the basic setup setup done (last part of handshake)
     * TODO implement finalizing the application session
     * @param session The {@link ApplicationSession} to finalize
     * @param applicationIdRequest {@link ApplicationIdRequest} containing the application ID (that should be whitelisted) encrypted with the session servers' public key
     * @return {@link ApplicationSessionResponse} containing the session key encrypted with the session applications' public key
     */
    public ApplicationSessionResponse finalizeApplicationSession(ApplicationSession session, ApplicationIdRequest applicationIdRequest) {
        return null;
    }
}
