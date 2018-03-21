package com.onior.crypto.demo.models.application;

import com.onior.crypto.demo.models.Session;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;
import java.util.UUID;

public class ApplicationSession implements Session {

    @Getter @Setter
    private String publicKeyClient;

    @Getter @Setter
    private String publicKeyServer;

    @Getter @Setter
    private String privateKeyServer;

    @Getter @Setter
    private String sessionKey;

    @Getter @Setter
    private String sessionId;

    @Getter @Setter
    private String refreshToken;

    @Getter @Setter
    private Date sessionStart;

    @Getter @Setter
    private Date sessionRefresh;

    public ApplicationSession() {
        this.sessionStart = new Date();
        this.sessionId = UUID.randomUUID().toString();
    }

}
