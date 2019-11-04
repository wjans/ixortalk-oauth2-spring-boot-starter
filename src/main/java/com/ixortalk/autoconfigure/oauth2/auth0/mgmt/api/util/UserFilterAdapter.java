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
package com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.util;

import com.auth0.client.mgmt.filter.UserFilter;
import com.auth0.json.mgmt.Page;

import static com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.Auth0ManagementAPI.PAGE_SIZE;
import static com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.util.PageUtil.getNextPage;

public class UserFilterAdapter implements FilterAdapter<UserFilter> {

    private UserFilter userFilter;

    public UserFilterAdapter() {
        this.userFilter = new UserFilter().withPage(0, PAGE_SIZE).withTotals(true);
    }

    @Override
    public UserFilterAdapter toNextPage(Page<?> page) {
        userFilter.withPage(getNextPage(page), PAGE_SIZE);
        return this;
    }

    @Override
    public UserFilter getFilter() {
        return userFilter;
    }
}
