package com.onior.crypto.demo.controllers.request;

import lombok.Getter;
import lombok.Setter;

public class SessionRefreshRequest {

    @Getter @Setter
    private String sessionId;

    @Getter @Setter
    private String sessionKey;

    public SessionRefreshRequest(String sessionId, String sessionKey) {
        this.sessionKey = sessionKey;
        this.sessionId = sessionId;
    }
}
