package com.onior.crypto.demo.controllers.response;

import lombok.Getter;
import lombok.Setter;

public class SessionRefreshResponse {

    @Getter @Setter
    private String refreshToken;

    @Getter @Setter
    private String sessionKey;
}
