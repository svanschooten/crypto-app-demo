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
        this.clientSessions.put(session.getSessionId(), session);
    }

    private void setSession(ApplicationSession session) {
        this.applicationSessions.put(session.getSessionId(), session);
    }

    private ClientSession createClientSession() {
        ClientSession session = new ClientSession();
        session = this.rsaService.fillSession(session);
        this.clientSessions.put(session.getSessionId(), session);
        return session;
    }

    public Session createSession(Session.Type type) {
        if (type == Session.Type.CLIENT) {
            return createClientSession();
        } else {
            return createApplicationSession();
        }
    }

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

    private ApplicationSession createApplicationSession() {
        ApplicationSession session = new ApplicationSession();
        session = this.ntruService.fillSession(session);
        setSession(session);
        return session;
    }

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

    public void destroySession(Session session, Session.Type type) {
        if (type == Session.Type.CLIENT) {
            clientSessions.remove(session.getSessionId());
        } else {
            applicationSessions.remove(session.getSessionId());
        }
    }

    public ApplicationSessionResponse finalizeApplicationSession(ApplicationSession session, ApplicationIdRequest applicationIdRequest) {
        return null;
    }
}
