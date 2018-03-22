package com.onior.crypto.demo.controllers.response;

import com.onior.crypto.demo.models.application.ApplicationSession;
import com.onior.crypto.demo.models.client.ClientSession;
import lombok.Getter;
import lombok.Setter;

public class ApplicationSessionResponse {

    @Getter @Setter
    private String sessionId;

    @Getter @Setter
    private String refreshToken;

    @Getter @Setter
    private String sessionKey;

    private ApplicationSessionResponse(String sessionId, String refreshToken, String sessionKey) {
        this.sessionId = sessionId;
        this.refreshToken = refreshToken;
        this.sessionKey = sessionKey;
    }

    public static ApplicationSessionResponse fromSession(ApplicationSession session) {
        return new ApplicationSessionResponse(session.getSessionId(), session.getRefreshToken(), session.getSessionKey());
    }
}
