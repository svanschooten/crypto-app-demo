package com.onior.crypto.demo.controllers.request;

import lombok.Getter;
import lombok.Setter;

public class ApplicationIdRequest {

    @Getter @Setter
    private String sessionId;

    @Getter @Setter
    private String applicationId;

}
