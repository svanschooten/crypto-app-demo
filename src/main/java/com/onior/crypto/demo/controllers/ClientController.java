package com.onior.crypto.demo.controllers;

import com.onior.crypto.demo.controllers.request.OTPRequest;
import com.onior.crypto.demo.controllers.request.SessionDeleteRequest;
import com.onior.crypto.demo.controllers.request.SessionKeyRequest;
import com.onior.crypto.demo.controllers.request.SessionRefreshRequest;
import com.onior.crypto.demo.controllers.response.ClientSessionResponse;
import com.onior.crypto.demo.controllers.response.PublicKeyResponse;
import com.onior.crypto.demo.controllers.response.SessionRefreshResponse;
import com.onior.crypto.demo.kms.SessionService;
import com.onior.crypto.demo.models.Session;
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
@RequestMapping(value = "/client/*")
public class ClientController extends BaseController {

    private final SessionService sessionService;

    @Autowired
    public ClientController(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    @RequestMapping(value = "otp", method = RequestMethod.POST)
    public PublicKeyResponse verifyOTP(@RequestBody OTPRequest otpRequest) {
        if (otpRequest == null) throw new IllegalArgumentException("No OTP key");
        // TODO verify otp?
        ClientSession session = (ClientSession) sessionService.createSession(Session.Type.CLIENT);
        return PublicKeyResponse.fromClientSession(session);
    }

    @RequestMapping(value = "session", method = RequestMethod.GET)
    public PublicKeyResponse startSessionNegotiation() {
        ClientSession session = (ClientSession) sessionService.createSession(Session.Type.CLIENT);
        return PublicKeyResponse.fromClientSession(session);
    }

    @RequestMapping(value = "session", method = RequestMethod.PUT)
    public SessionRefreshResponse refreshSession(@RequestBody SessionRefreshRequest sessionRefreshRequest) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidParameterSpecException,
            InvalidKeySpecException {
        if (sessionRefreshRequest == null) throw new IllegalArgumentException("No refresh data");
        ClientSession session = (ClientSession) sessionService.getSession(sessionRefreshRequest.getSessionId(), Session.Type.CLIENT);
        return sessionService.refreshSession(session, sessionRefreshRequest, Session.Type.CLIENT);
    }

    @RequestMapping(value = "session", method = RequestMethod.DELETE)
    public void deleteSession(@RequestBody SessionDeleteRequest sessionDeleteRequest) {
        if (sessionDeleteRequest == null) throw new IllegalArgumentException("No session data");
        ClientSession session = (ClientSession) sessionService.getSession(sessionDeleteRequest.getSessionId(), Session.Type.CLIENT);
        sessionService.destroySession(session, Session.Type.CLIENT);
    }

    @RequestMapping(value = "session", method = RequestMethod.POST)
    public ClientSessionResponse setupSession(@RequestBody SessionKeyRequest sessionKeyRequest) throws
            BadPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, IllegalBlockSizeException,
            InvalidParameterSpecException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {
        if (sessionKeyRequest == null) throw new IllegalArgumentException("No session data");
        ClientSession session = (ClientSession) sessionService.getSession(sessionKeyRequest.getSessionId(), Session.Type.CLIENT);
        return sessionService.finalizeClientSession(session, sessionKeyRequest);
    }
}
