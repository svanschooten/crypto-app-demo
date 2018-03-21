package com.onior.crypto.demo.models.client;

import com.onior.crypto.demo.models.Session;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;
import java.util.UUID;

public class ClientSession implements Session {

    @Getter @Setter
    private String publicKey;

    @Getter @Setter
    private String privateKey;

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

    public ClientSession() {
        this.sessionStart = new Date();
        this.sessionId = UUID.randomUUID().toString();
    }

}
