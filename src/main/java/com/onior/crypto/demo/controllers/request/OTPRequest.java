package com.onior.crypto.demo.controllers.request;

import lombok.Getter;
import lombok.Setter;

public class OTPRequest {

    @Getter @Setter
    private String otp;

    public OTPRequest(String otp) {
        this.otp = otp;
    }
}
