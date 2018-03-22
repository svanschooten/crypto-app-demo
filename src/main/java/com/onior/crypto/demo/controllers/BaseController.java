package com.onior.crypto.demo.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

public class BaseController {

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<String> processError(IllegalArgumentException ex) {
        return response("Invalid request", ex.getMessage(), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(NullPointerException.class)
    public ResponseEntity<String> processError(NullPointerException ex) {
        return response("Not found", ex.getMessage(), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler({InvalidKeySpecException.class, InvalidParameterSpecException.class, UnsupportedEncodingException.class,
            BadPaddingException.class, IllegalBlockSizeException.class, NoSuchPaddingException.class,
            NoSuchAlgorithmException.class, InvalidKeyException.class, InvalidAlgorithmParameterException.class})
    public ResponseEntity<String> processCryptoError(Exception ex) {
        return response("Cryptographic error", ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private static ResponseEntity<String> response(String message, String reason, HttpStatus httpStatus) {
        return new ResponseEntity<>(String.format("{\"error\" : \"%s\",\"reason\" : \"%s\"}", message, reason), httpStatus);
    }
}
