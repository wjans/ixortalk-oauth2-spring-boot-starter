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

import com.auth0.json.mgmt.Role;
import com.auth0.json.mgmt.users.User;

import java.util.Set;

import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;

public class Auth0Roles {

    private Auth0ManagementAPI auth0ManagementAPI;

    public Auth0Roles(Auth0ManagementAPI auth0ManagementAPI) {
        this.auth0ManagementAPI = auth0ManagementAPI;
    }

    public Set<String> getAllRoleNames() {
        return auth0ManagementAPI.listRolesByName().keySet();
    }

    public void addRole(String roleName) {
        auth0ManagementAPI.addRole(roleName);
    }

    public void deleteRole(String roleName) {
        auth0ManagementAPI.deleteRole(auth0ManagementAPI.listRolesByName().get(roleName).getId());
    }

    public Set<String> getUsersRoles(String email) {
        return auth0ManagementAPI.getUserByEmail(email)
                .map(User::getId)
                .map(id -> auth0ManagementAPI.getUsersRoles(id)
                        .stream()
                        .map(Role::getName)
                        .collect(toSet()))
                .orElseThrow(() -> new Auth0RuntimeException("User with email '" + email + "' not found"));
    }

    public Set<String> getUsersInRole(String roleName) {
        return auth0ManagementAPI
                .getUsersInRole(auth0ManagementAPI.listRolesByName().get(roleName).getId())
                .stream()
                .map(User::getEmail)
                .collect(toSet());
    }

    public void assignRolesToUser(String email, Set<String> roleNamesToAssign) {
        if (roleNamesToAssign.isEmpty()) {
            return;
        }

        auth0ManagementAPI.getUserByEmail(email)
                .ifPresent(user -> this.auth0ManagementAPI.assignRolesToUser(
                        user.getId(),
                        roleNamesToAssign.stream()
                                .map(roleName -> this.auth0ManagementAPI.listRolesByName().get(roleName).getId())
                                .collect(toList())
                ));

    }

    public void removeRolesFromUser(String email, Set<String> roleNamesToRemove) {
        if (roleNamesToRemove.isEmpty()) {
            return;
        }

        auth0ManagementAPI.getUserByEmail(email)
                .ifPresent(user -> auth0ManagementAPI.removeRolesFromUser(
                                user.getId(),
                                roleNamesToRemove.stream()
                                        .map(roleName -> this.auth0ManagementAPI.listRolesByName().get(roleName).getId())
                                        .collect(toList())
                ));
    }
}