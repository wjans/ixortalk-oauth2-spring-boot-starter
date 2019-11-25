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

import com.auth0.json.mgmt.users.User;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;

public class Auth0Users {

    private Auth0ManagementAPI auth0ManagementAPI;

    public Auth0Users(Auth0ManagementAPI auth0ManagementAPI) {
        this.auth0ManagementAPI = auth0ManagementAPI;
    }

    public Map<String, UserInfo> listUsersByEmail() {
        return this.auth0ManagementAPI
                .listUsersByEmail()
                .entrySet()
                .stream()
                .collect(toMap(
                        Map.Entry::getKey,
                        user -> toUserInfo(user.getValue())));
    }

    public Optional<UserInfo> getUserInfo(String email) {
        return ofNullable(auth0ManagementAPI.listUsersByEmail().get(email)).map(Auth0Users::toUserInfo);
    }

    public boolean userExists(String email) {
        return auth0ManagementAPI.listUsersByEmail().containsKey(email);
    }

    public void createBlockedUser(String email, String password, String firstName, String lastName, String langKey, List<String> roleNamesToAssign) {
        auth0ManagementAPI.createBlockedUserWithRoles(
                email,
                password,
                firstName,
                lastName,
                langKey,
                roleNamesToAssign.stream().map(roleName -> this.auth0ManagementAPI.listRolesByName().get(roleName).getId()).collect(toList()));
    }

    public void unblockUser(String email) {
        ofNullable(auth0ManagementAPI.listUsersByEmail().get(email)).ifPresent(user -> auth0ManagementAPI.unblockUser(user.getId()));
    }

    private static UserInfo toUserInfo(User user) {
        return new UserInfo(
                user.getEmail(),
                user.getGivenName(),
                user.getFamilyName());
    }
}
