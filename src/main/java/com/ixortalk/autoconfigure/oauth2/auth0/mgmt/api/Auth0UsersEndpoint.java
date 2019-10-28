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
package com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api;

import com.auth0.client.mgmt.ManagementAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.mgmt.users.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Optional.empty;
import static java.util.Optional.of;
import static java.util.function.Function.identity;
import static java.util.stream.Collectors.toMap;
import static org.apache.commons.lang.StringUtils.isBlank;

public class Auth0UsersEndpoint {

    private static final Logger LOGGER = LoggerFactory.getLogger(Auth0UsersEndpoint.class);

    private ManagementAPI auth0ManagementAPI;

    private OAuth2RestTemplate auth0ManagementAPIRestTemplate;

    public Auth0UsersEndpoint(ManagementAPI auth0ManagementAPI, OAuth2RestTemplate auth0ManagementAPIRestTemplate) {
        this.auth0ManagementAPI = auth0ManagementAPI;
        this.auth0ManagementAPIRestTemplate = auth0ManagementAPIRestTemplate;
    }

    public Map<String, UserInfo> listUsersByEmail() {
        return listUsers().stream().map(this::createUserInfo).collect(toMap(UserInfo::getEmail, identity()));
    }

    public Optional<UserInfo> getUserInfo(String email) {
        List<User> users = listUsersByEmail(email);
        if (users.isEmpty()) {
            return empty();
        }

        return
                of(users
                        .stream()
                        .filter(user -> !isBlank(user.getFamilyName()))
                        .findFirst()
                        .map(this::createUserInfo)
                        .orElse(new UserInfo(email)));
    }

    public boolean userExists(String email) {
        return !listUsersByEmail(email).isEmpty();
    }

    private List<User> listUsersByEmail(String email) {
        try {
            auth0ManagementAPI.setApiToken(auth0ManagementAPIRestTemplate.getAccessToken().getValue());
            return auth0ManagementAPI
                    .users()
                    .listByEmail(email, null)
                    .execute();
        } catch (Auth0Exception e) {
            LOGGER.error("Error retrieving user '" + email + "' :" + e.getMessage(), e);
            throw new RuntimeException("Error retrieving user '" + email + "' :" + e.getMessage(), e);
        }
    }

    private List<User> listUsers() {
        try {
            auth0ManagementAPI.setApiToken(auth0ManagementAPIRestTemplate.getAccessToken().getValue());
            return auth0ManagementAPI
                    .users()
                    .list(null)
                    .execute()
                    .getItems();
        } catch (Auth0Exception e) {
            LOGGER.error("Error retrieving users: " + e.getMessage(), e);
            throw new RuntimeException("Error retrieving users: " + e.getMessage(), e);
        }
    }

    private UserInfo createUserInfo(User user) {
        return new UserInfo(user.getEmail(), user.getGivenName(), user.getFamilyName());
    }
}