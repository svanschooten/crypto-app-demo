package com.onior.crypto.demo.controllers.request;

import lombok.Getter;
import lombok.Setter;

public class SessionTestRequest {

    @Setter @Getter
    private String sessionId;

    @Setter @Getter
    private String testText;

    public SessionTestRequest(String testText, String sessionId) {
        this.testText = testText;
        this.sessionId = sessionId;
    }
}
