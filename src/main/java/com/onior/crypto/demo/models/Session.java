package com.onior.crypto.demo.models;

import lombok.Getter;
import lombok.Setter;

import java.util.Date;
import java.util.UUID;

public class Session {

    @Getter @Setter
    private String sessionId;

    @Getter @Setter
    private String refreshToken;

    @Getter @Setter
    private Date sessionStart;

    @Getter @Setter
    private Date sessionRefresh;

    @Getter @Setter
    private String sessionKey;

    public Session() {
        this.sessionStart = new Date();
        this.sessionId = UUID.randomUUID().toString();
    }
}
