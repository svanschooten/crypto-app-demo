package com.onior.crypto.demo.controllers;

import com.onior.crypto.demo.controllers.request.ApplicationIdRequest;
import com.onior.crypto.demo.controllers.request.PublicKeyRequest;
import com.onior.crypto.demo.controllers.request.SessionDeleteRequest;
import com.onior.crypto.demo.controllers.request.SessionRefreshRequest;
import com.onior.crypto.demo.controllers.response.ApplicationSessionResponse;
import com.onior.crypto.demo.controllers.response.PublicKeyResponse;
import com.onior.crypto.demo.controllers.response.SessionRefreshResponse;
import com.onior.crypto.demo.kms.SessionService;
import com.onior.crypto.demo.models.Session;
import com.onior.crypto.demo.models.application.ApplicationSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

@RestController
@RequestMapping(value = "/application/*")
public class ApplicationController {

    private final SessionService sessionService;

    @Autowired
    public ApplicationController(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    @RequestMapping(value = "initialize", method = RequestMethod.POST)
    public PublicKeyResponse startSessionNegotiation(@RequestBody PublicKeyRequest publicKeyRequest) {
        if (publicKeyRequest == null) throw new IllegalArgumentException("Missing public key");
        ApplicationSession session = (ApplicationSession) sessionService.createSession(Session.Type.APPLICATION);
        return PublicKeyResponse.fromApplicationSession(session);
    }

    @RequestMapping(value = "session", method = RequestMethod.POST)
    public ApplicationSessionResponse setupSession(@RequestBody ApplicationIdRequest applicationIdRequest) {
        if (applicationIdRequest == null) throw new IllegalArgumentException("Missing application ID");
        ApplicationSession session = (ApplicationSession) sessionService.getSession(applicationIdRequest.getSessionId(), Session.Type.APPLICATION);
        return sessionService.finalizeApplicationSession(session, applicationIdRequest);
    }

    @RequestMapping(value = "session", method = RequestMethod.DELETE)
    public void deleteSession(@RequestBody SessionDeleteRequest sessionDeleteRequest) {
        if (sessionDeleteRequest == null) throw new IllegalArgumentException("No session data");
        ApplicationSession session = (ApplicationSession) sessionService.getSession(sessionDeleteRequest.getSessionId(), Session.Type.APPLICATION);
        sessionService.destroySession(session, Session.Type.APPLICATION);
    }

    @RequestMapping(value = "session", method = RequestMethod.PUT)
    public SessionRefreshResponse refreshSession(@RequestBody SessionRefreshRequest sessionRefreshRequest) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidParameterSpecException,
            InvalidKeySpecException {
        if (sessionRefreshRequest == null) throw new IllegalArgumentException("No refresh data");
        ApplicationSession session = (ApplicationSession) sessionService.getSession(sessionRefreshRequest.getSessionId(), Session.Type.APPLICATION);
        return sessionService.refreshSession(session, sessionRefreshRequest, Session.Type.APPLICATION);
    }

}
