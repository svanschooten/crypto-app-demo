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
        ClientSession session = this.sessionService.createClientSession();
        return PublicKeyResponse.fromClientSession(session);
    }

    @RequestMapping(value = "session", method = RequestMethod.GET)
    public PublicKeyResponse startSessionNegotiation() {
        ClientSession session = this.sessionService.createClientSession();
        return PublicKeyResponse.fromClientSession(session);
    }

    @RequestMapping(value = "session", method = RequestMethod.POST)
    public ClientSessionResponse setupSession(@RequestBody SessionKeyRequest sessionKeyRequest) {
        if (sessionKeyRequest == null) return null;
        ClientSession session = this.sessionService.getClientSession(sessionKeyRequest.getSessionId());
        if (session == null) return null;
        // TODO decrypt sessionKeyRequest.getSessionKey() and expand to AES key.
        // TODO generate refresh token.
        // TODO return session response encrypted with AES key
        return ClientSessionResponse.fromClientSession(session);
    }
}
