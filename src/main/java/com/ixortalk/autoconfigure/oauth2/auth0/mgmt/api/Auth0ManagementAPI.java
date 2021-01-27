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
import com.auth0.client.mgmt.filter.UserFilter;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.mgmt.Role;
import com.auth0.json.mgmt.tickets.EmailVerificationTicket;
import com.auth0.json.mgmt.users.User;
import com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.util.RolesFilterAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.util.PageUtil.listItemsFromAllPages;
import static java.util.Collections.singletonMap;
import static java.util.function.Function.identity;
import static java.util.stream.Collectors.toMap;

public class Auth0ManagementAPI {

    public static final String AUTH_0_USER_BY_ID_CACHE = "auth0UserByIdCache";
    public static final String AUTH_0_USER_BY_EMAIL_CACHE = "auth0UserByEmailCache";
    public static final String AUTH_0_ROLE_CACHE = "auth0RoleCache";
    public static final String AUTH_0_USER_ROLE_CACHE = "auth0UserRoleCache";
    public static final String AUTH_0_ROLE_USER_CACHE = "auth0RoleUserCache";

    public static final int PAGE_SIZE = 100;

    private static final Logger LOGGER = LoggerFactory.getLogger(Auth0ManagementAPI.class);

    private ManagementAPI managementAPI;

    private OAuth2AuthorizeRequest authorizeRequest;

    private String domain;

    private String createUserConnection;

    private AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientServiceOAuth2AuthorizedClientManager;

    public Auth0ManagementAPI(String domain, String createUserConnection, AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientServiceOAuth2AuthorizedClientManager, OAuth2AuthorizeRequest authorizeRequest) {
        this.domain = domain;
        this.createUserConnection = createUserConnection;
        this.authorizedClientServiceOAuth2AuthorizedClientManager = authorizedClientServiceOAuth2AuthorizedClientManager;
        this.authorizeRequest = authorizeRequest;
    }

    @Cacheable(cacheNames = AUTH_0_USER_BY_ID_CACHE, sync = true)
    public Optional<User> getUserById(String userId) {
        try {
            return Optional.ofNullable(getManagementAPI().users().get(userId, new UserFilter())
                    .execute());
        } catch (Auth0Exception e) {
            LOGGER.error("Error retrieving user: " + e.getMessage(), e);
            throw new Auth0RuntimeException("Error retrieving user: " + e.getMessage(), e);
        }
    }

    @Cacheable(cacheNames = AUTH_0_USER_BY_EMAIL_CACHE, sync = true)
    public Optional<User> getUserByEmail(String userEmail) {
        try {
            List<User> users = getManagementAPI().users().listByEmail(userEmail, new UserFilter())
                    .execute();

            if (users.size() > 1) {
                String notUniqueErrorMessage = String.format("Trying to fetch unique user by email '%s' which is found %d times", userEmail, users.size());
                LOGGER.error(notUniqueErrorMessage);
                throw new IllegalStateException(notUniqueErrorMessage);
            }

            return users.stream().findFirst();
        } catch (Auth0Exception e) {
            LOGGER.error("Error retrieving user: " + e.getMessage(), e);
            throw new Auth0RuntimeException("Error retrieving user: " + e.getMessage(), e);
        }
    }

    @Cacheable(cacheNames = AUTH_0_ROLE_CACHE, sync = true)
    public Map<String, Role> listRolesByName() {
        try {
            return
                    listItemsFromAllPages(getManagementAPI().roles()::list, new RolesFilterAdapter())
                            .stream()
                            .collect(toMap(Role::getName, identity()));
        } catch (Auth0Exception e) {
            LOGGER.error("Error retrieving roles: " + e.getMessage(), e);
            throw new Auth0RuntimeException("Error retrieving roles: " + e.getMessage(), e);
        }
    }

    @Cacheable(cacheNames = AUTH_0_USER_ROLE_CACHE, sync = true)
    public List<Role> getUsersRoles(String userId) {
        try {
            return
                    getManagementAPI()
                            .users()
                            .listRoles(userId, null)
                            .execute()
                            .getItems();
        } catch (Auth0Exception e) {
            LOGGER.error("Error retrieving roles for user '" + userId + "' :" + e.getMessage(), e);
            throw new Auth0RuntimeException("Error retrieving roles for user '" + userId + "' :" + e.getMessage(), e);
        }
    }

    @Cacheable(cacheNames = AUTH_0_ROLE_USER_CACHE, sync = true)
    public List<User> getUsersInRole(String roleId) {
        try {
            return
                    getManagementAPI()
                            .roles()
                            .listUsers(roleId, null)
                            .execute()
                            .getItems();
        } catch (Auth0Exception e) {
            LOGGER.error("Error retrieving users in role '" + roleId + "' :" + e.getMessage(), e);
            throw new Auth0RuntimeException("Error retrieving users in role '" + roleId + "' :" + e.getMessage(), e);
        }
    }

    @CacheEvict(cacheNames = AUTH_0_ROLE_CACHE, allEntries = true)
    public void addRole(String roleName) {
        try {
            Role role = new Role();
            role.setName(roleName);
            role.setDescription("Created role via Management API");
            getManagementAPI()
                    .roles()
                    .create(role)
                    .execute();
        } catch (Auth0Exception e) {
            LOGGER.error("Error creating role '" + roleName + "' :" + e.getMessage(), e);
            throw new Auth0RuntimeException("Error creating role '" + roleName + "' :" + e.getMessage(), e);
        }
    }

    @CacheEvict(cacheNames = {AUTH_0_ROLE_CACHE, AUTH_0_USER_ROLE_CACHE, AUTH_0_ROLE_USER_CACHE}, allEntries = true)
    public void deleteRole(String roleId) {
        try {
            getManagementAPI()
                    .roles()
                    .delete(roleId)
                    .execute();
        } catch (Auth0Exception e) {
            LOGGER.error("Error deleting role '" + roleId + "' :" + e.getMessage(), e);
            throw new Auth0RuntimeException("Error deleting role '" + roleId + "' :" + e.getMessage(), e);
        }
    }

    @CacheEvict(cacheNames = {AUTH_0_USER_ROLE_CACHE, AUTH_0_ROLE_USER_CACHE}, allEntries = true)
    public void assignRolesToUser(String userId, List<String> roleIds) {
        try {
            getManagementAPI()
                    .users()
                    .addRoles(userId, roleIds)
                    .execute();
        } catch (Auth0Exception e) {
            LOGGER.error("Error assigning roles to user '" + userId + "' :" + e.getMessage(), e);
            throw new Auth0RuntimeException("Error assigning roles to user '" + userId + "' :" + e.getMessage(), e);
        }
    }

    @CacheEvict(cacheNames = {AUTH_0_USER_ROLE_CACHE, AUTH_0_ROLE_USER_CACHE}, allEntries = true)
    public void removeRolesFromUser(String userId, List<String> roleIds) {
        try {
            getManagementAPI()
                    .users()
                    .removeRoles(userId, roleIds)
                    .execute();
        } catch (Auth0Exception e) {
            LOGGER.error("Error removing roles from user '" + userId + "' :" + e.getMessage(), e);
            throw new Auth0RuntimeException("Error removing roles from user '" + userId + "' :" + e.getMessage(), e);
        }
    }

    @Caching(evict = {
            @CacheEvict(cacheNames = AUTH_0_USER_BY_EMAIL_CACHE, key = "#email"),
            @CacheEvict(cacheNames = AUTH_0_ROLE_USER_CACHE, allEntries = true)
    })
    public void createBlockedUserWithRoles(String email, String password, String firstName, String lastName, String langKey, List<String> roleIds) {
        User user = new User();
        user.setEmail(email);
        user.setEmailVerified(true);
        user.setPassword(password);
        user.setGivenName(firstName);
        user.setFamilyName(lastName);
        user.setBlocked(true);
        user.setConnection(createUserConnection);
        user.setUserMetadata(singletonMap("user_lang", langKey));

        try {
            User createdUser =
                    getManagementAPI()
                            .users()
                            .create(user)
                            .execute();
            assignRolesToUser(createdUser.getId(), roleIds);
        } catch (Auth0Exception e) {
            LOGGER.error("Error creating blocked user '" + email + "' :" + e.getMessage(), e);
            throw new Auth0RuntimeException("Error creating blocked user '" + email + "' :" + e.getMessage(), e);
        }
    }

    public String createEmailVerificationTicket(String userId, String resultUrl, int timeToLiveInSeconds) {
        EmailVerificationTicket emailVerificationTicket = new EmailVerificationTicket(userId);
        emailVerificationTicket.setResultUrl(resultUrl);
        emailVerificationTicket.setTTLSeconds(timeToLiveInSeconds);
        try {
            return getManagementAPI()
                    .tickets()
                    .requestEmailVerification(emailVerificationTicket)
                    .execute()
                    .getTicket();
        } catch (Auth0Exception e) {
            LOGGER.error("Error creating email verification ticket for user '" + userId + "' :" + e.getMessage(), e);
            throw new Auth0RuntimeException("Error creating email verification ticket for user '" + userId + "' :" + e.getMessage(), e);
        }
    }

    public void unblockUser(String userId) {
        User unblocked = new User();
        unblocked.setBlocked(false);
        updateUser(userId, unblocked);
    }

    public void updateProfilePicture(String userId, String profilePictureUrl) {
        User updated = new User();
        updated.setPicture(profilePictureUrl);
        updateUser(userId, updated);
    }

    public void updateAppMetadata(String userId, Map<String, Object> appMetadata) {
        User updated = new User();
        updated.setAppMetadata(appMetadata);
        updateUser(userId, updated);
    }

    private void updateUser(String userId, User update) {
        try {
            getManagementAPI()
                    .users()
                    .update(userId, update)
                    .execute();
        } catch (Auth0Exception e) {
            LOGGER.error("Error updating user '" + userId + "' :" + e.getMessage(), e);
            throw new Auth0RuntimeException("Error updating user '" + userId + "' :" + e.getMessage(), e);
        }
    }

    private ManagementAPI getManagementAPI() {
        if (this.managementAPI == null) {
            this.managementAPI = new ManagementAPI(domain, getAccessToken());
        } else {
            managementAPI.setApiToken(getAccessToken());
        }
        return managementAPI;
    }

    private String getAccessToken() {
        return this.authorizedClientServiceOAuth2AuthorizedClientManager.authorize(authorizeRequest).getAccessToken().getTokenValue();
    }
}
