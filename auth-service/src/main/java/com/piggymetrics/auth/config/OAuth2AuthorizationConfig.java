package com.piggymetrics.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.piggymetrics.auth.service.security.MongoUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * @author cdov
 */
@Configuration
public class OAuth2AuthorizationConfig {

   /* @Autowired
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;*/

    @Autowired
    private MongoUserDetailsService userDetailsService;

    @Autowired
    private Environment env;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint(
                                new LoginUrlAuthenticationEntryPoint("/login"))
                );

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                .csrf().disable()
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

   /* @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }*/

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        /*clients.inMemory()
                .withClient("browser")
                .authorizedGrantTypes("refresh_token", "password")
                .scopes("ui")
                .and()
                .withClient("account-service")
                .secret(env.getProperty("ACCOUNT_SERVICE_PASSWORD"))
                .authorizedGrantTypes("client_credentials", "refresh_token")
                .scopes("server")
                .and()
                .withClient("statistics-service")
                .secret(env.getProperty("STATISTICS_SERVICE_PASSWORD"))
                .authorizedGrantTypes("client_credentials", "refresh_token")
                .scopes("server")
                .and()
                .withClient("notification-service")
                .secret(env.getProperty("NOTIFICATION_SERVICE_PASSWORD"))
                .authorizedGrantTypes("client_credentials", "refresh_token")
                .scopes("server");*/

        List<RegisteredClient> clientList = new ArrayList<>();
        {
            RegisteredClient acService = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("browser")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                    .scope("ui")
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                    .build();
            clientList.add(acService);
        }

        {
            RegisteredClient acService = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("account-service")
                    .clientSecret("{noop}" + env.getProperty("ACCOUNT_SERVICE_PASSWORD"))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .scope("server")
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                    .build();
            clientList.add(acService);
        }

        {
            RegisteredClient acService = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("notification-service")
                    .clientSecret("{noop}" + env.getProperty("STATISTICS_SERVICE_PASSWORD"))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .scope("server")
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                    .build();
            clientList.add(acService);
        }

        {
            RegisteredClient acService = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("statistics-service")
                    .clientSecret("{noop}" + env.getProperty("NOTIFICATION_SERVICE_PASSWORD"))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .scope("server")
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                    .build();
            clientList.add(acService);
        }

        return new InMemoryRegisteredClientRepository(clientList);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder().build();
    }


}
