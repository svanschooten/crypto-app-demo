package com.onior.crypto.demo.models.application;

import com.onior.crypto.demo.models.Session;
import lombok.Getter;
import lombok.Setter;

public class ApplicationSession extends Session {

    @Getter @Setter
    private String publicKeyClient;

    @Getter @Setter
    private String publicKeyServer;

    @Getter @Setter
    private String privateKeyServer;

    public ApplicationSession() {
        super();
    }

}
