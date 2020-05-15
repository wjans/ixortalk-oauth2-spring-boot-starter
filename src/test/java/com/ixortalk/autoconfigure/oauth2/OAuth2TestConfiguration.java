/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2016-present IxorTalk CVBA
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.ixortalk.autoconfigure.oauth2;

import com.github.tomakehurst.wiremock.http.Request;
import com.github.tomakehurst.wiremock.matching.MatchResult;
import com.github.tomakehurst.wiremock.matching.ValueMatcher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.Jwt;

import javax.inject.Inject;
import java.util.Map;

import static com.google.common.collect.Lists.newArrayList;
import static com.ixortalk.test.util.Randomizer.nextString;
import static org.apache.commons.lang3.StringUtils.substringAfter;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.security.oauth2.client.registration.ClientRegistration.withRegistrationId;
import static org.springframework.security.oauth2.common.OAuth2AccessToken.BEARER_TYPE;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS;

@Configuration
public class OAuth2TestConfiguration {

    public static final String AUTH_0_MANAGEMENT_API_TEST_CLIENT_ID = "auth0-management-api-test-client-id";

    public static final String INTERNAL_API_TEST_CLIENT_ID = "internal-api-test-client-id";
    public static final String INTERNAL_API_TEST_CLIENT_SECRET = "internal-api-test-client-secret";

    public static final String RETRIEVED_ADMIN_TOKEN = nextString("retrievedInternalAPIAdminToken");

    @Inject
    private IxorTalkConfigProperties ixorTalkConfigProperties;

    @Value("${ixortalk.test.token-server.port}")
    private int tokenServerPort;

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return registrationId -> {
            if (registrationId.equals(ixorTalkConfigProperties.getAuth0().getManagementApi().getClientRegistrationId())) {
                return withRegistrationId(registrationId)
                        .clientId(AUTH_0_MANAGEMENT_API_TEST_CLIENT_ID)
                        .tokenUri("http://localhost:" + tokenServerPort + "/token")
                        .authorizationGrantType(CLIENT_CREDENTIALS)
                        .build();
            } else if (registrationId.equals(ixorTalkConfigProperties.getSecurity().getFeign().getServiceToServiceClientRegistrationId())) {
                return withRegistrationId(registrationId)
                        .clientId(INTERNAL_API_TEST_CLIENT_ID)
                        .clientSecret(INTERNAL_API_TEST_CLIENT_SECRET)
                        .tokenUri("http://localhost:" + tokenServerPort + "/token")
                        .authorizationGrantType(CLIENT_CREDENTIALS)
                        .build();
            }

            return null;
        };
    }

    public static ValueMatcher<Request> retrievedAdminTokenAuthorizationHeader() {
        return request -> {
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            String bearerToken = substringAfter(authorizationHeader, BEARER_TYPE + " ");
            return MatchResult.of(bearerToken.equals(RETRIEVED_ADMIN_TOKEN));
        };
    }

    public static Jwt buildJwtToken(String jwtToken, String subject, Map<String, String> additionalClaims, String... roles) {
        return Jwt.withTokenValue(jwtToken)
                .header("alg", "none")
                .subject(subject)
                .claim("scope", newArrayList(roles))
                .claims(claims -> claims.putAll(additionalClaims))
                .build();
    }
}