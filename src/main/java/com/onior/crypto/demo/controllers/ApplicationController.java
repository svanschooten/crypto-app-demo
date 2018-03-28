package com.onior.crypto.demo.controllers;

import com.onior.crypto.demo.controllers.request.*;
import com.onior.crypto.demo.controllers.response.ApplicationSessionResponse;
import com.onior.crypto.demo.controllers.response.PublicKeyResponse;
import com.onior.crypto.demo.controllers.response.SessionRefreshResponse;
import com.onior.crypto.demo.controllers.response.SessionTestResponse;
import com.onior.crypto.demo.kms.AESService;
import com.onior.crypto.demo.kms.SessionService;
import com.onior.crypto.demo.models.Session;
import com.onior.crypto.demo.models.application.ApplicationSession;
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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

@RestController
@RequestMapping(value = "/session/application/*")
public class ApplicationController {

    private final SessionService sessionService;

    @Autowired
    public ApplicationController(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    @RequestMapping(value = "start", method = RequestMethod.POST)
    public PublicKeyResponse startSessionNegotiation(@RequestBody PublicKeyRequest publicKeyRequest) {
        if (publicKeyRequest == null) throw new IllegalArgumentException("Missing public key");
        ApplicationSession session = (ApplicationSession) sessionService.createSession(Session.Type.APPLICATION);
        return PublicKeyResponse.fromApplicationSession(session);
    }

    @RequestMapping(value = "finalize", method = RequestMethod.POST)
    public ApplicationSessionResponse setupSession(@RequestBody ApplicationIdRequest applicationIdRequest) {
        if (applicationIdRequest == null) throw new IllegalArgumentException("Missing application ID");
        ApplicationSession session = (ApplicationSession) sessionService.getSession(applicationIdRequest.getSessionId(), Session.Type.APPLICATION);
        return sessionService.finalizeApplicationSession(session, applicationIdRequest);
    }

    @RequestMapping(value = "delete", method = RequestMethod.DELETE)
    public void deleteSession(@RequestBody SessionIdRequest sessionIdRequest) {
        if (sessionIdRequest == null) throw new IllegalArgumentException("No session data");
        ApplicationSession session = (ApplicationSession) sessionService.getSession(sessionIdRequest.getSessionId(), Session.Type.APPLICATION);
        sessionService.destroySession(session, Session.Type.APPLICATION);
    }

    @RequestMapping(value = "refresh", method = RequestMethod.POST)
    public SessionRefreshResponse refreshSession(@RequestBody SessionRefreshRequest sessionRefreshRequest) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidParameterSpecException,
            InvalidKeySpecException {
        if (sessionRefreshRequest == null) throw new IllegalArgumentException("No refresh data");
        ApplicationSession session = (ApplicationSession) sessionService.getSession(sessionRefreshRequest.getSessionId(), Session.Type.APPLICATION);
        return sessionService.refreshSession(session, sessionRefreshRequest, Session.Type.APPLICATION);
    }

    @RequestMapping(value = "test", method = RequestMethod.POST)
    public SessionTestResponse testSecuritySetup(@RequestBody SessionTestRequest testRequest) throws
            NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException,
            UnsupportedEncodingException, InvalidKeyException, InvalidParameterSpecException,
            InvalidAlgorithmParameterException {
        if (testRequest == null) throw new IllegalArgumentException("Invalid test request");
        ClientSession session = (ClientSession) sessionService.getSession(testRequest.getSessionId(), Session.Type.APPLICATION);
        AESService aesService = sessionService.getAesService();
        String testText = aesService.decrypt(testRequest.getTestText(), session.getSessionKey());
        if (!testText.equals("application")) throw new IllegalArgumentException("Invalid test decryption result");
        return new SessionTestResponse(aesService.encrypt("server", session.getSessionKey()));
    }

}
