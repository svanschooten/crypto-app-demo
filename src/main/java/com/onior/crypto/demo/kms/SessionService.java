package com.onior.crypto.demo.kms;

import com.onior.crypto.demo.models.Session;
import com.onior.crypto.demo.models.application.ApplicationSession;
import com.onior.crypto.demo.models.client.ClientSession;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Service
public class SessionService {

    private HashMap<String, Session> clientSessions;
    private HashMap<String, Session> applicationSessions;

    public SessionService() {
        this.clientSessions = new HashMap<>();
        this.applicationSessions = new HashMap<>();
    }

    public ClientSession createClientSession() {
        ClientSession session = new ClientSession();
        this.clientSessions.put(session.getSessionId(), session);
        return session;
    }

    public ApplicationSession createApplicationSession() {
        ApplicationSession session = new ApplicationSession();
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
