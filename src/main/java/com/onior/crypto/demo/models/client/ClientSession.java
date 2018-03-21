package com.onior.crypto.demo.models.client;

import com.onior.crypto.demo.models.Session;
import lombok.Getter;
import lombok.Setter;

public class ClientSession extends Session {

    @Getter @Setter
    private String publicKey;

    @Getter @Setter
    private String privateKey;

    public ClientSession() {
        super();
    }

}
