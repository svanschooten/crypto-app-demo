package com.onior.crypto.demo.controllers.request;

import com.onior.crypto.demo.models.application.ApplicationSession;
import com.onior.crypto.demo.models.client.ClientSession;
import lombok.Getter;
import lombok.Setter;

public class PublicKeyRequest {

    @Getter @Setter
    private String publicKey;

}
