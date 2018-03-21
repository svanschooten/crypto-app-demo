package com.onior.crypto.demo.controllers.request;

import lombok.Setter;
import lombok.Getter;

public class SessionKeyRequest {

    @Setter @Getter
    private String sessionKey;

    @Setter @Getter
    private String sessionId;

    public SessionKeyRequest(String sessionKey, String sessionId) {
        this.sessionKey = sessionKey;
        this.sessionId = sessionId;
    }
}
