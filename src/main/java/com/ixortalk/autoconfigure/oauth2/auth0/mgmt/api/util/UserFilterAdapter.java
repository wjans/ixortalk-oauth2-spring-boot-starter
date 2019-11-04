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
