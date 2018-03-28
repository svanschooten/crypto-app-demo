package com.onior.crypto.demo.controllers.response;

import lombok.Getter;
import lombok.Setter;

public class SessionIdResponse {

    @Getter @Setter
    private String sessionId;

    public SessionIdResponse(String sessionId) {
        this.sessionId = sessionId;
    }
}
