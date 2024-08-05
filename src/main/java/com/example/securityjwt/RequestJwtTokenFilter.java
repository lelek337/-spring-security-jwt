package com.example.securityjwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.channels.AcceptPendingException;
import java.nio.file.AccessDeniedException;
import java.util.function.Function;

public class RequestJwtTokenFilter extends OncePerRequestFilter {

    private RequestMatcher requestMatcher = new AntPathRequestMatcher("/jwt/tokens", HttpMethod.POST.name());
    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();
    private Function<Authentication, Token> refreshTokenFactory = new DefaultRefreshTokenFactory();
    private Function<Token, Token> accessTokenFactory = new DefaultAccessTokenFactory();
    private Function<Token, String> refreshTokenSerializer = Object::toString;
    private Function<Token, String> accessTokenSerializer = Object::toString;
    private ObjectMapper objectMapper = new ObjectMapper();
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (this.requestMatcher.matches(request)) {
            if (this.securityContextRepository.containsContext(request)) {
                var context = this.securityContextRepository.loadDeferredContext(request).get();
                if (context != null && !(context.getAuthentication() instanceof PreAuthenticatedAuthenticationToken)) {
                    var refreshToken = this.refreshTokenFactory.apply(context.getAuthentication());
                    var accessToken = this.accessTokenFactory.apply(refreshToken);

                    response.setStatus(HttpServletResponse.SC_OK);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    this.objectMapper.writeValue(response.getWriter(),
                            new Tokens(this.accessTokenSerializer.apply(accessToken),
                                    accessToken.expiresAt().toString(),
                                    this.refreshTokenSerializer.apply(refreshToken),
                                    refreshToken.expiresAt().toString()));
                    return;
                }
            }

            throw new AccessDeniedException("User must be authenticated");
        }
        filterChain.doFilter(request, response);
    }

    public void setAccessTokenSerializer(Function<Token, String> accessTokenSerializer) {
    }

    public void setRefreshTokenSerializer(Function<Token, String> refreshTokenSerializer) {
    }
}
