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
import com.auth0.json.mgmt.users.User;
import com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.util.RolesFilterAdapter;
import com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.util.UserFilterAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;

import java.util.List;
import java.util.Map;

import static com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.util.PageUtil.listItemsFromAllPages;
import static java.util.function.Function.identity;
import static java.util.stream.Collectors.toMap;

public class Auth0ManagementAPI {

    public static final String AUTH_0_USER_CACHE = "auth0UserCache";
    public static final String AUTH_0_ROLE_CACHE = "auth0RoleCache";
    public static final String AUTH_0_USER_ROLE_CACHE = "auth0UserRoleCache";

    public static final int PAGE_SIZE = 100;

    private static final Logger LOGGER = LoggerFactory.getLogger(Auth0ManagementAPI.class);

    private ManagementAPI managementAPI;

    private OAuth2RestTemplate auth0ManagementAPIRestTemplate;

    public Auth0ManagementAPI(ManagementAPI managementAPI, OAuth2RestTemplate auth0ManagementAPIRestTemplate) {
        this.managementAPI = managementAPI;
        this.auth0ManagementAPIRestTemplate = auth0ManagementAPIRestTemplate;
    }

    @Cacheable(cacheNames = AUTH_0_USER_CACHE, sync = true)
    public Map<String, User> listUsersByEmail() {
        try {
            return
                    listItemsFromAllPages(getManagementAPI().users()::list, new UserFilterAdapter())
                            .stream()
                            .collect(toMap(User::getEmail, identity()));
        } catch (Auth0Exception e) {
            LOGGER.error("Error retrieving users: " + e.getMessage(), e);
            throw new RuntimeException("Error retrieving users: " + e.getMessage(), e);
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
            throw new RuntimeException("Error retrieving roles: " + e.getMessage(), e);
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
            throw new RuntimeException("Error retrieving roles for user '" + userId + "' :" + e.getMessage(), e);
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
            throw new RuntimeException("Error creating role '" + roleName + "' :" + e.getMessage(), e);
        }
    }

    @CacheEvict(cacheNames = {AUTH_0_ROLE_CACHE, AUTH_0_USER_ROLE_CACHE}, allEntries = true)
    public void deleteRole(String roleId) {
        try {
            getManagementAPI()
                    .roles()
                    .delete(roleId)
                    .execute();
        } catch (Auth0Exception e) {
            LOGGER.error("Error deleting role '" + roleId + "' :" + e.getMessage(), e);
            throw new RuntimeException("Error deleting role '" + roleId + "' :" + e.getMessage(), e);
        }
    }

    @CacheEvict(cacheNames = AUTH_0_USER_ROLE_CACHE, key = "#userId")
    public void assignRolesToUser(String userId, List<String> roleIds) {
        try {
            getManagementAPI()
                    .users()
                    .addRoles(userId, roleIds)
                    .execute();
        } catch (Auth0Exception e) {
            LOGGER.error("Error assigning roles to user '" + userId + "' :" + e.getMessage(), e);
            throw new RuntimeException("Error assigning roles to user '" + userId + "' :" + e.getMessage(), e);
        }
    }

    @CacheEvict(cacheNames = AUTH_0_USER_ROLE_CACHE, key = "#userId")
    public void removeRolesFromUser(String userId, List<String> roleIds) {
        try {
            getManagementAPI()
                    .users()
                    .removeRoles(userId, roleIds)
                    .execute();
        } catch (Auth0Exception e) {
            LOGGER.error("Error removing roles from user '" + userId + "' :" + e.getMessage(), e);
            throw new RuntimeException("Error removing roles from user '" + userId + "' :" + e.getMessage(), e);
        }
    }

    private ManagementAPI getManagementAPI() {
        managementAPI.setApiToken(auth0ManagementAPIRestTemplate.getAccessToken().getValue());
        return managementAPI;
    }
}
