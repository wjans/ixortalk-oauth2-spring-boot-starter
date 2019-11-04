package com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.util;

import com.auth0.client.mgmt.filter.RolesFilter;
import com.auth0.json.mgmt.Page;

import static com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.Auth0ManagementAPI.PAGE_SIZE;
import static com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.util.PageUtil.getNextPage;

public class RolesFilterAdapter implements FilterAdapter<RolesFilter> {

    private RolesFilter rolesFilter;

    public RolesFilterAdapter() {
        this.rolesFilter = new RolesFilter().withPage(0, PAGE_SIZE).withTotals(true);
    }

    @Override
    public RolesFilterAdapter toNextPage(Page<?> page) {
        rolesFilter.withPage(getNextPage(page), PAGE_SIZE);
        return this;
    }

    @Override
    public RolesFilter getFilter() {
        return rolesFilter;
    }
}
