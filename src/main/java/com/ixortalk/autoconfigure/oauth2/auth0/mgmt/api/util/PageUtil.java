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
