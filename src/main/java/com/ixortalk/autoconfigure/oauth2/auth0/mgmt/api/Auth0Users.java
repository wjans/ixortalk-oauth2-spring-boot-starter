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

import static java.util.stream.Collectors.toList;

public class Auth0Users {

    private Auth0ManagementAPI auth0ManagementAPI;

    public Auth0Users(Auth0ManagementAPI auth0ManagementAPI) {
        this.auth0ManagementAPI = auth0ManagementAPI;
    }

    public Optional<UserInfo> getUserInfo(String email) {
        return auth0ManagementAPI.getUserByEmail(email).map(Auth0Users::toUserInfo);
    }

    public boolean userExists(String email) {
        return auth0ManagementAPI.getUserByEmail(email).isPresent();
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

    public String createEmailVerificationTicket(String userId, String resultUrl, int timeToLiveInSeconds) {
        return auth0ManagementAPI.getUserById(userId)
                        .map(user -> auth0ManagementAPI.createEmailVerificationTicket(user.getId(), resultUrl, timeToLiveInSeconds))
                        .orElseThrow(() -> new Auth0RuntimeException("User with id '" + userId + "' not found"));
    }

    public void unblockUser(String email) {
        auth0ManagementAPI.getUserByEmail(email).ifPresent(user -> auth0ManagementAPI.unblockUser(user.getId()));
    }

    public void updateProfilePicture(String email, String profilePictureUrl) {
        auth0ManagementAPI.getUserByEmail(email).ifPresent(user -> auth0ManagementAPI.updateProfilePicture(user.getId(), profilePictureUrl));
    }

    public void updateAppMetadata(String email, Map<String, Object> appMetadata) {
        auth0ManagementAPI.getUserByEmail(email).ifPresent(user -> auth0ManagementAPI.updateAppMetadata(user.getId(), appMetadata));
    }

    private static UserInfo toUserInfo(User user) {
        return new UserInfo(
                user.getEmail(),
                user.getGivenName(),
                user.getFamilyName(),
                user.getPicture());
    }
}
