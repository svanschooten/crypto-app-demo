package com.onior.crypto.demo;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

import java.security.Security;

@SpringBootApplication(exclude = {SecurityAutoConfiguration.class })
public class DemoApplication {

	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		Security.addProvider(new BouncyCastlePQCProvider());
		SpringApplication.run(DemoApplication.class, args);
	}
}
