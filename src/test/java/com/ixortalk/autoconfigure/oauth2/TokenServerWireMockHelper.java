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
package com.ixortalk.autoconfigure.oauth2;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.json.JSONException;
import org.json.JSONObject;

import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.ixortalk.autoconfigure.oauth2.OAuth2TestConfiguration.INTERNAL_API_TEST_CLIENT_ID;
import static com.ixortalk.autoconfigure.oauth2.OAuth2TestConfiguration.INTERNAL_API_TEST_CLIENT_SECRET;
import static com.ixortalk.autoconfigure.oauth2.OAuth2TestConfiguration.RETRIEVED_ADMIN_TOKEN;
import static org.springframework.security.oauth2.common.OAuth2AccessToken.BEARER_TYPE;

public class TokenServerWireMockHelper {

    public static void stubAdminToken(WireMockRule wireMockClassRule) {
        try {
            wireMockClassRule.stubFor(post(urlEqualTo("/token"))
                    .withBasicAuth(INTERNAL_API_TEST_CLIENT_ID, INTERNAL_API_TEST_CLIENT_SECRET)
                    .willReturn(okJson(
                            new JSONObject()
                                    .put("access_token", RETRIEVED_ADMIN_TOKEN)
                                    .put("token_type", BEARER_TYPE)
                                    .toString())));
        } catch (JSONException e) {
            throw new RuntimeException("Error stubbing token endpoint: " + e.getMessage(), e);
        }
    }
}
