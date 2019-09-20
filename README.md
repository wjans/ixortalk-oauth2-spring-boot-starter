# ixortalk-oauth2-spring-boot-starter

Starter module containing configurable OAuth2 setup for IxorTalk modules.  See `com.ixortalk.autoconfigure.oauth2.OAuth2AutoConfiguration` for more details.

When no further configuration is present in the module itself, all resources will be protected by default:

```
@Configuration
@ConditionalOnMissingBean(IxorTalkHttpSecurityConfigurer.class)
public static class DefaultIxorTalkHttpSecurityConfigurerConfiguration {

    @Bean
    public IxorTalkHttpSecurityConfigurer defaultIxorTalkHttpSecurityConfigurer() {
        return http -> http.authorizeRequests().anyRequest().authenticated();
    }
}
```

## Plain OAuth2

When including this module without any configuration, a plain OAuth2 configuration will be included, securing all resources.

## Auth0 

Auth0 configuration will be enabled automatically when an Auth0 domain is configured via property `ixortalk.auth0.domain`.

## Further customizations

Further customizations to the web security can be made iregardless of the used OAuth2 provider.

```
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

@Configuration
public class SecurityConfig implements IxorTalkHttpSecurityConfigurer {

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/docs/**").permitAll()
                .anyRequest().authenticated();
    }
}
```
