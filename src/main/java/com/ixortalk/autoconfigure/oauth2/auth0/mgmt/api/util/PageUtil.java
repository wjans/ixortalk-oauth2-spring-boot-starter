package com.ixortalk.autoconfigure.oauth2.auth0.mgmt.api.util;

import com.auth0.client.mgmt.filter.BaseFilter;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.mgmt.Page;
import com.auth0.net.Request;

import java.util.List;
import java.util.function.Function;

public class PageUtil {

    public static int getNextPage(Page<?> page) {
        return (page.getStart() / page.getLimit()) + 1;
    }

    public static boolean hasNextPage(Page<?> page) {
        return page.getStart() + page.getLimit() <= page.getTotal();
    }

    public static <FILTER extends BaseFilter, PAGE extends Page<RESULT>, RESULT> List<RESULT> listItemsFromAllPages(
            Function<FILTER, Request<PAGE>> listCall,
            FilterAdapter<FILTER> filter) throws Auth0Exception {
        PAGE page = listCall.apply(filter.getFilter()).execute();
        List<RESULT> allItems = page.getItems();
        while (hasNextPage(page)) {
            page = listCall.apply(filter.toNextPage(page).getFilter()).execute();
            allItems.addAll(page.getItems());
        }
        return allItems;
    }
}
