package com.example.securityjwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.text.ParseException;

@SpringBootApplication
public class SecurityJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityJwtApplication.class, args);
	}
		@Bean
	public JwtAuthenticationConfigurer jwtAuthenticationConfigurer (
			@Value("${jwt.access-token-key}") String accessTokenKey,
			@Value("${jwt.refresh-token-key}") String refreshTokenKey
		) throws ParseException, JOSEException {
		return new JwtAuthenticationConfigurer()
				.accessTokenSerializer(new AccessTokenJwsStringSerializer(
						new MACSigner(OctetSequenceKey.parse(accessTokenKey))
				))
				.refreshTokenSerializer(new RefreshTokenJweStringSerializer(
						new DirectEncrypter(OctetSequenceKey.parse(refreshTokenKey))
				));
		}
}