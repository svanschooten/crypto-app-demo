package com.onior.crypto.demo.controllers.response;

import com.onior.crypto.demo.models.client.ClientSession;
import lombok.Getter;
import lombok.Setter;

public class ClientSessionResponse {

    @Getter @Setter
    private String sessionId;

    @Getter @Setter
    private String refreshToken;

    public ClientSessionResponse(String sessionId, String refreshToken) {
        this.sessionId = sessionId;
        this.refreshToken = refreshToken;
    }

    public static ClientSessionResponse fromClientSession(ClientSession session) {
        return new ClientSessionResponse(session.getSessionId(), session.getRefreshToken());
    }
}
