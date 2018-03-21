package com.onior.crypto.demo.kms;

import com.onior.crypto.demo.models.Session;
import com.onior.crypto.demo.models.application.ApplicationSession;
import com.onior.crypto.demo.models.client.ClientSession;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.UUID;

@Service
public class SessionService {

    private HashMap<String, Session> clientSessions;
    private HashMap<String, Session> applicationSessions;
    private RSAService rsaService;
    private NTRUService ntruService;

    @Autowired
    public SessionService(RSAService rsaService, NTRUService ntruService) {
        this.clientSessions = new HashMap<>();
        this.applicationSessions = new HashMap<>();
        this.rsaService = rsaService;
        this.ntruService = ntruService;
    }

    private String generateRefreshToken() {
        return Base64.toBase64String(UUID.randomUUID().toString().getBytes());
    }

    public ClientSession createClientSession() {
        ClientSession session = new ClientSession();
        session = (ClientSession) this.rsaService.fillSession(session);
        session.setRefreshToken(this.generateRefreshToken());
        this.clientSessions.put(session.getSessionId(), session);
        return session;
    }

    public ApplicationSession createApplicationSession() {
        ApplicationSession session = new ApplicationSession();
        session = (ApplicationSession) this.ntruService.fillSession(session);
        session.setRefreshToken(this.generateRefreshToken());
        this.applicationSessions.put(session.getSessionId(), session);
        return session;
    }

    public ClientSession getClientSession(String sessionId) {
        return (ClientSession) this.clientSessions.get(sessionId);
    }

    public ApplicationSession getApplicationSession(String sessionId) {
        return (ApplicationSession) this.applicationSessions.get(sessionId);
    }
}
