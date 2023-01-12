package com.piggymetrics.auth.customizer.jwt;

import com.piggymetrics.auth.customizer.jwt.impl.DefaultJwtCustomizerHandler;
import com.piggymetrics.auth.customizer.jwt.impl.OAuth2AuthenticationTokenJwtCustomizerHandler;
import com.piggymetrics.auth.customizer.jwt.impl.UsernamePasswordAuthenticationTokenJwtCustomizerHandler;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

public interface JwtCustomizerHandler {

    void customize(JwtEncodingContext jwtEncodingContext);

    static JwtCustomizerHandler getJwtCustomizerHandler() {

        JwtCustomizerHandler defaultJwtCustomizerHandler = new DefaultJwtCustomizerHandler();
        JwtCustomizerHandler oauth2AuthenticationTokenJwtCustomizerHandler = new OAuth2AuthenticationTokenJwtCustomizerHandler(defaultJwtCustomizerHandler);
        JwtCustomizerHandler usernamePasswordAuthenticationTokenJwtCustomizerHandler = new UsernamePasswordAuthenticationTokenJwtCustomizerHandler(oauth2AuthenticationTokenJwtCustomizerHandler);
        return usernamePasswordAuthenticationTokenJwtCustomizerHandler;


    }

}
