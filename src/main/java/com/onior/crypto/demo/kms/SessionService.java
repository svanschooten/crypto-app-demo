package com.onior.crypto.demo.kms;

import com.onior.crypto.demo.controllers.request.SessionKeyRequest;
import com.onior.crypto.demo.controllers.response.ClientSessionResponse;
import com.onior.crypto.demo.models.Session;
import com.onior.crypto.demo.models.application.ApplicationSession;
import com.onior.crypto.demo.models.client.ClientSession;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.HashMap;
import java.util.UUID;
import java.util.logging.Logger;

@Service
public class SessionService {

    private HashMap<String, Session> clientSessions;
    private HashMap<String, Session> applicationSessions;
    private RSAService rsaService;
    private NTRUService ntruService;
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

    private String generateRefreshToken() {
        return Base64.toBase64String(UUID.randomUUID().toString().getBytes());
    }

    private void setSession(ClientSession session) {
        this.applicationSessions.put(session.getSessionId(), session);
    }

    private void setSession(ApplicationSession session) {
        this.applicationSessions.put(session.getSessionId(), session);
    }

    public ClientSession createClientSession() {
        ClientSession session = new ClientSession();
        session = (ClientSession) this.rsaService.fillSession(session);
        this.clientSessions.put(session.getSessionId(), session);
        return session;
    }

    public ClientSession getClientSession(String sessionId) {
        return (ClientSession) this.clientSessions.get(sessionId);
    }

    public ClientSessionResponse finalizeSession(ClientSession session, SessionKeyRequest sessionKeyRequest) throws
            InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, NoSuchPaddingException, InvalidParameterSpecException, UnsupportedEncodingException {

        session.setRefreshToken(this.generateRefreshToken());

        ClientSessionResponse response = ClientSessionResponse.fromClientSession(session);

        String sessionKeyPassphrase = rsaService.decrypt(sessionKeyRequest.getSessionKey(), session.getPrivateKey());
        String sessionKey = aesService.expandKey(sessionKeyPassphrase);

        logger.info("Sessionkey: " + sessionKey);
        logger.info("Refresh token: " + response.getRefreshToken());

        session.setSessionKey(sessionKey);
        setSession(session);
        response.setRefreshToken(aesService.encrypt(response.getRefreshToken(), sessionKey));

        return response;
    }

    public ApplicationSession createApplicationSession() {
        ApplicationSession session = new ApplicationSession();
        session = (ApplicationSession) this.ntruService.fillSession(session);
        setSession(session);
        return session;
    }

    public ApplicationSession getApplicationSession(String sessionId) {
        return (ApplicationSession) this.applicationSessions.get(sessionId);
    }
}
