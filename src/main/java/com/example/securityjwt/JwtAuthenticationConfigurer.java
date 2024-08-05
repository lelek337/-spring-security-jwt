package com.example.securityjwt;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.function.Function;

public class JwtAuthenticationConfigurer extends AbstractHttpConfigurer<JwtAuthenticationConfigurer, HttpSecurity> {

    private Function<Token, String> refreshTokenSerializer = Object::toString;
    private Function<Token, String> accessTokenSerializer = Object::toString;
    @Override
    public void init(HttpSecurity builder) throws Exception {
        var csrfConfigurer = builder.getConfigurer(CsrfConfigurer.class);
        if (csrfConfigurer != null) {
            csrfConfigurer.ignoringRequestMatchers(new AntPathRequestMatcher("/jwt/token/", "POST"));
        }
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        builder.addFilterAfter(new RequestJwtTokenFilter(), ExceptionTranslationFilter.class);
        var filter = new RequestJwtTokenFilter();
        filter.setAccessTokenSerializer(this.accessTokenSerializer);
        filter.setRefreshTokenSerializer(this.refreshTokenSerializer);
    }

    public JwtAuthenticationConfigurer RefreshTokenSerializer(Function<Token, String> refreshTokenSerializer) {
        this.refreshTokenSerializer = refreshTokenSerializer;
        return this;
    }

    public JwtAuthenticationConfigurer AccessTokenSerializer(Function<Token, String> accessTokenSerializer) {
        this.accessTokenSerializer = accessTokenSerializer;
        return this;
    }
}