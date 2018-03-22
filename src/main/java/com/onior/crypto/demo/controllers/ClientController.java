package com.onior.crypto.demo.controllers;

import com.onior.crypto.demo.controllers.request.OTPRequest;
import com.onior.crypto.demo.controllers.request.SessionKeyRequest;
import com.onior.crypto.demo.controllers.response.ClientSessionResponse;
import com.onior.crypto.demo.controllers.response.PublicKeyResponse;
import com.onior.crypto.demo.kms.SessionService;
import com.onior.crypto.demo.models.client.ClientSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

@RestController
@RequestMapping(value = "/client/*")
public class ClientController {

    private final SessionService sessionService;

    @Autowired
    public ClientController(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    @RequestMapping(value = "otp", method = RequestMethod.POST)
    public PublicKeyResponse verifyOTP(@RequestBody OTPRequest otpRequest) {
        if (otpRequest == null) return null;
        // TODO verify otp?
        ClientSession session = sessionService.createClientSession();
        return PublicKeyResponse.fromClientSession(session);
    }

    @RequestMapping(value = "session", method = RequestMethod.GET)
    public PublicKeyResponse startSessionNegotiation() {
        ClientSession session = sessionService.createClientSession();
        return PublicKeyResponse.fromClientSession(session);
    }

    @RequestMapping(value = "session", method = RequestMethod.POST)
    public ClientSessionResponse setupSession(@RequestBody SessionKeyRequest sessionKeyRequest) throws
            BadPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, IllegalBlockSizeException,
            InvalidParameterSpecException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {
        if (sessionKeyRequest == null) return null;
        ClientSession session = sessionService.getClientSession(sessionKeyRequest.getSessionId());
        if (session == null) return null;
        return sessionService.finalizeSession(session, sessionKeyRequest);
    }
}
