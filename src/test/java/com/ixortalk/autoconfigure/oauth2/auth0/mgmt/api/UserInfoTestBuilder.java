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

import static com.ixortalk.test.util.Randomizer.nextString;

public class UserInfoTestBuilder {

    private String email = nextString("user") + "@ixortalk.com";
    private String firstName;
    private String lastName;
    private String profilePictureUrl;

    private UserInfoTestBuilder() {
    }

    public static UserInfoTestBuilder aUserInfo() {
        return new UserInfoTestBuilder();
    }

    public UserInfo build() {
        return new UserInfo(email, firstName, lastName, profilePictureUrl);
    }

    public UserInfoTestBuilder withEmail(String email) {
        this.email = email;
        return this;
    }

    public UserInfoTestBuilder withFirstName(String firstName) {
        this.firstName = firstName;
        return this;
    }

    public UserInfoTestBuilder withLastName(String lastName) {
        this.lastName = lastName;
        return this;
    }

    public UserInfoTestBuilder withProfilePictureUrl(String profilePictureUrl) {
        this.profilePictureUrl = profilePictureUrl;
        return this;
    }
}