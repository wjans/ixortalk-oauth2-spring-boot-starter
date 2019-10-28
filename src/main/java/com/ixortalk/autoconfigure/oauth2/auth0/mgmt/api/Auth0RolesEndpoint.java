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
import com.auth0.client.mgmt.filter.RolesFilter;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.mgmt.Role;
import com.auth0.json.mgmt.users.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;

import java.util.List;
import java.util.Set;

import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;

public class Auth0RolesEndpoint {

    private static final Logger LOGGER = LoggerFactory.getLogger(Auth0RolesEndpoint.class);

    private ManagementAPI auth0ManagementAPI;

    private OAuth2RestTemplate auth0ManagementAPIRestTemplate;

    public Auth0RolesEndpoint(ManagementAPI auth0ManagementAPI, OAuth2RestTemplate auth0ManagementAPIRestTemplate) {
        this.auth0ManagementAPI = auth0ManagementAPI;
        this.auth0ManagementAPIRestTemplate = auth0ManagementAPIRestTemplate;
    }

    public Set<String> getAllRoleNames() {
        try {
            auth0ManagementAPI.setApiToken(auth0ManagementAPIRestTemplate.getAccessToken().getValue());
            return
                    auth0ManagementAPI
                            .roles()
                            .list(null)
                            .execute()
                            .getItems()
                            .stream()
                            .map(Role::getName)
                            .collect(toSet());
        } catch (Auth0Exception e) {
            LOGGER.error("Error retrieving all roles :" + e.getMessage(), e);
            throw new RuntimeException("Error retrieving all roles :" + e.getMessage(), e);
        }
    }

    public void addRole(String roleName) {
        try {
            Role role = new Role();
            role.setName(roleName);
            role.setDescription("Created role via Management API");
            auth0ManagementAPI.setApiToken(auth0ManagementAPIRestTemplate.getAccessToken().getValue());
            auth0ManagementAPI
                    .roles()
                    .create(role)
                    .execute();
        } catch (Auth0Exception e) {
            LOGGER.error("Error creating role '" + roleName + "' :" + e.getMessage(), e);
            throw new RuntimeException("Error creating role '" + roleName + "' :" + e.getMessage(), e);
        }
    }

    public void deleteRole(String roleName) {
        try {
            auth0ManagementAPI.setApiToken(auth0ManagementAPIRestTemplate.getAccessToken().getValue());
            auth0ManagementAPI
                    .roles()
                    .delete(getRole(roleName).getId())
                    .execute();
        } catch (Auth0Exception e) {
            LOGGER.error("Error deleting role '" + roleName + "' :" + e.getMessage(), e);
            throw new RuntimeException("Error deleting role '" + roleName + "' :" + e.getMessage(), e);
        }
    }

    public Set<String> getUsersRoles(String email) {
        try {
            auth0ManagementAPI.setApiToken(auth0ManagementAPIRestTemplate.getAccessToken().getValue());
            return
                    auth0ManagementAPI
                            .users()
                            .listRoles(getUser(email).getId(), null)
                            .execute()
                            .getItems()
                            .stream()
                            .map(Role::getName)
                            .collect(toSet());
        } catch (Auth0Exception e) {
            LOGGER.error("Error retrieving roles for user '" + email + "' :" + e.getMessage(), e);
            throw new RuntimeException("Error retrieving roles for user '" + email + "' :" + e.getMessage(), e);
        }
    }

    public void assignRolesToUser(String email, Set<String> roleNamesToAssign) {
        try {
            auth0ManagementAPI.setApiToken(auth0ManagementAPIRestTemplate.getAccessToken().getValue());
            auth0ManagementAPI
                    .users()
                    .addRoles(getUser(email).getId(), getRoles(roleNamesToAssign).stream().map(Role::getId).collect(toList()))
                    .execute();
        } catch (Auth0Exception e) {
            LOGGER.error("Error assigning roles to user '" + email + "' :" + e.getMessage(), e);
            throw new RuntimeException("Error assigning roles to user '" + email + "' :" + e.getMessage(), e);
        }
    }

    public void removeRolesFromUser(String email, Set<String> roleNamesToRemove) {
        try {
            auth0ManagementAPI.setApiToken(auth0ManagementAPIRestTemplate.getAccessToken().getValue());
            auth0ManagementAPI
                    .users()
                    .removeRoles(getUser(email).getId(), getRoles(roleNamesToRemove).stream().map(Role::getId).collect(toList()))
                    .execute();
        } catch (Auth0Exception e) {
            LOGGER.error("Error removing roles from user '" + email + "' :" + e.getMessage(), e);
            throw new RuntimeException("Error removing roles from user '" + email + "' :" + e.getMessage(), e);
        }
    }

    private Role getRole(String roleName) throws Auth0Exception {
        List<Role> roles =
                auth0ManagementAPI
                        .roles()
                        .list(new RolesFilter().withName(roleName))
                        .execute()
                        .getItems();

        if (roles.isEmpty()) {
            throw new IllegalArgumentException("No role found with name '" + roleName + "'");
        }

        if (roles.size() > 1) {
            throw new IllegalArgumentException("Multiple roles found with name '" + roleName + "'");
        }

        return roles.get(0);
    }

    private List<Role> getRoles(Set<String> roleNames) throws Auth0Exception {
        return auth0ManagementAPI
                .roles()
                .list(null)
                .execute()
                .getItems()
                .stream()
                .filter(role -> roleNames.contains(role.getName()))
                .collect(toList());
    }

    private User getUser(String email) throws Auth0Exception {
        List<User> users =
                auth0ManagementAPI
                        .users()
                        .listByEmail(email, null)
                        .execute();

        if (users.isEmpty()) {
            throw new IllegalArgumentException("No user found with email '" + email + "'");
        }

        if (users.size() > 1) {
            throw new IllegalArgumentException("Multiple users found with email '" + email + "'");
        }

        return users.get(0);
    }
}