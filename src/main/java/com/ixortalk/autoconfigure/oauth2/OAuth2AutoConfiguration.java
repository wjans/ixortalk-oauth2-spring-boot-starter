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

import com.auth0.spring.security.api.JwtWebSecurityConfigurer;
import org.springframework.boot.actuate.autoconfigure.ManagementServerProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.NoneNestedConditions;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;

import javax.inject.Inject;
import java.util.List;

import static java.lang.String.format;
import static org.springframework.util.StringUtils.isEmpty;

@Configuration
@EnableWebSecurity
public class OAuth2AutoConfiguration {

    @Configuration
    @EnableConfigurationProperties(IxorTalkAuth0ConfigProperties.class)
    @ConditionalOnProperty(prefix = "ixortalk.auth0", name = "domain")
    protected static class Auth0Configuration implements IxorTalkHttpSecurityConfigurer {

        @Inject
        private IxorTalkAuth0ConfigProperties ixorTalkAuth0ConfigProperties;

        @Override
        public void configure(HttpSecurity http) throws Exception {
            JwtWebSecurityConfigurer
                    .forRS256(ixorTalkAuth0ConfigProperties.getAudience(), format("https://%s/", ixorTalkAuth0ConfigProperties.getDomain()))
                    .configure(http);
        }
    }

    @Configuration
    @Conditional(NoAuth0Condition.class)
    @Import(ResourceServerConfiguration.class)
    protected static class PlainOAuth2Configuration {

    }

    @Configuration
    @ConditionalOnMissingBean(IxorTalkHttpSecurityConfigurer.class)
    public static class DefaultIxorTalkHttpSecurityConfigurerConfiguration {

        @Bean
        public IxorTalkHttpSecurityConfigurer defaultIxorTalkHttpSecurityConfigurer() {
            return http -> http.authorizeRequests().anyRequest().authenticated();
        }

    }

    @Configuration
    protected static class IxorTalkWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter implements ResourceServerConfigurer {

        @Inject
        private ManagementServerProperties managementServerProperties;

        @Inject
        private List<IxorTalkHttpSecurityConfigurer> ixorTalkHttpSecurityConfigurers;

        @Override
        public void configure(WebSecurity web) {
            if (!isEmpty(managementServerProperties.getContextPath())) {
                web.ignoring().antMatchers(managementServerProperties.getContextPath() + "/**");
            }
        }

        @Override
        public void configure(ResourceServerSecurityConfigurer resources) throws Exception {

        }

        @Override
        public void configure(HttpSecurity http) throws Exception {
            for (IxorTalkHttpSecurityConfigurer ixorTalkHttpSecurityConfigurer : ixorTalkHttpSecurityConfigurers) {
                ixorTalkHttpSecurityConfigurer.configure(http);
            }
        }
    }

    static class NoAuth0Condition extends NoneNestedConditions {

        NoAuth0Condition() {
            super(ConfigurationPhase.PARSE_CONFIGURATION);
        }

        @ConditionalOnProperty(prefix = "ixortalk.auth0", name = "domain")
        static class Auth0Condition {

        }

    }
}
