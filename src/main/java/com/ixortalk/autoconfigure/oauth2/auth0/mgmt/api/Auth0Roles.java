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

import java.util.Set;

import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;

public class Auth0Roles {

    private Auth0ManagementAPI auth0ManagementAPI;

    public Auth0Roles(Auth0ManagementAPI auth0ManagementAPI) {
        this.auth0ManagementAPI = auth0ManagementAPI;
    }

    public Set<String> getAllRoleNames() {
        return this.auth0ManagementAPI.listRolesByName().keySet();
    }

    public void addRole(String roleName) {
        this.auth0ManagementAPI.addRole(roleName);
    }

    public void deleteRole(String roleName) {
        this.auth0ManagementAPI.deleteRole(this.auth0ManagementAPI.listRolesByName().get(roleName).getId());
    }

    public Set<String> getUsersRoles(String email) {
        return this.auth0ManagementAPI
                .getUsersRoles(this.auth0ManagementAPI.listUsersByEmail().get(email).getId())
                .stream()
                .map(Role::getName)
                .collect(toSet());
    }

    public void assignRolesToUser(String email, Set<String> roleNamesToAssign) {
        if (roleNamesToAssign.isEmpty()) {
            return;
        }

        this.auth0ManagementAPI
                .assignRolesToUser(
                        this.auth0ManagementAPI.listUsersByEmail().get(email).getId(),
                        roleNamesToAssign.stream().map(roleName -> this.auth0ManagementAPI.listRolesByName().get(roleName).getId()).collect(toList())
                );
    }

    public void removeRolesFromUser(String email, Set<String> roleNamesToRemove) {
        if (roleNamesToRemove.isEmpty()) {
            return;
        }

        this.auth0ManagementAPI
                .removeRolesFromUser(
                        this.auth0ManagementAPI.listUsersByEmail().get(email).getId(),
                        roleNamesToRemove.stream().map(roleName -> this.auth0ManagementAPI.listRolesByName().get(roleName).getId()).collect(toList())
                );
    }
}