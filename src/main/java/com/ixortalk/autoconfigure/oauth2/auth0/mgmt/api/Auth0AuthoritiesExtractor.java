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
import com.auth0.json.mgmt.Role;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;

import java.util.List;
import java.util.Map;

import static com.auth0.jwt.impl.PublicClaims.SUBJECT;
import static java.util.stream.Collectors.toList;

public class Auth0AuthoritiesExtractor implements AuthoritiesExtractor {

    private ManagementAPI auth0ManagementAPI;

    private OAuth2RestTemplate auth0ManagementAPIRestTemplate;

    public Auth0AuthoritiesExtractor(ManagementAPI auth0ManagementAPI, OAuth2RestTemplate auth0ManagementAPIRestTemplate) {
        this.auth0ManagementAPI = auth0ManagementAPI;
        this.auth0ManagementAPIRestTemplate = auth0ManagementAPIRestTemplate;
    }

    @Override
    public List<GrantedAuthority> extractAuthorities(Map<String, Object> map) {
        try {
            auth0ManagementAPI.setApiToken(auth0ManagementAPIRestTemplate.getAccessToken().getValue());
            return
                    auth0ManagementAPI
                            .users()
                            .listRoles(map.get(SUBJECT).toString(), null)
                            .execute()
                            .getItems()
                            .stream()
                            .map(Role::getName)
                            .map(SimpleGrantedAuthority::new)
                            .collect(toList());
        } catch (Auth0Exception e) {
            throw new RuntimeException("Error retrieving authorities: " + e.getMessage(), e);
        }
    }
}
