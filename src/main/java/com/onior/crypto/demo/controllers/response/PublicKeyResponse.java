package com.onior.crypto.demo.controllers.response;

import com.onior.crypto.demo.models.application.ApplicationSession;
import com.onior.crypto.demo.models.client.ClientSession;
import lombok.Getter;
import lombok.Setter;

public class PublicKeyResponse {

    @Getter @Setter
    private String publicKey;

    @Getter @Setter
    private String sessionId;

    public PublicKeyResponse(String publicKey, String sessionId) {
        this.publicKey = publicKey;
        this.sessionId = sessionId;
    }

    public static PublicKeyResponse fromClientSession(ClientSession session) {
        return new PublicKeyResponse(session.getPublicKey(), session.getSessionId());
    }

    public static PublicKeyResponse fromApplicationSession(ApplicationSession session) {
        return new PublicKeyResponse(session.getPublicKeyServer(), session.getSessionId());
    }
}
