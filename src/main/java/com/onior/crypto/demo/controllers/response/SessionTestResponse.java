package com.onior.crypto.demo.controllers.response;

import lombok.Getter;
import lombok.Setter;

public class SessionTestResponse {

    @Getter @Setter
    private String testResponse;

    public SessionTestResponse(String testResponse) {
        this.testResponse = testResponse;
    }
}
