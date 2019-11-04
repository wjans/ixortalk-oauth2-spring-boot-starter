package com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.util;

import com.auth0.client.mgmt.filter.BaseFilter;
import com.auth0.json.mgmt.Page;

public interface FilterAdapter<FILTER extends BaseFilter> {

    FilterAdapter<FILTER> toNextPage(Page<?> page);

    FILTER getFilter();
}
