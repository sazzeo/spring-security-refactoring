package nextstep.autoconfigure;

import nextstep.oauth2.userinfo.OAuth2UserService;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.config.DelegatingFilterProxy;
import nextstep.security.config.FilterChainProxy;
import nextstep.security.config.SecurityFilterChain;
import nextstep.security.userdetails.UserDetailsService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.security.ConditionalOnDefaultWebSecurity;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;

import java.util.List;

@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

    private final AuthenticationManager authenticationManager;

    public DefaultSecurityConfig(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Bean
    public DelegatingFilterProxy delegatingFilterProxy(List<SecurityFilterChain> securityFilterChains) {
        return new DelegatingFilterProxy(new FilterChainProxy(securityFilterChains));
    }


    @Bean
    @Order(SecurityProperties.BASIC_AUTH_ORDER)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) {
        return http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/members").hasAuthority("ADMIN")
                        .requestMatchers("/members/me").authenticated()
                        .anyRequest().permitAll()
                )
                .formLogin(formLogin -> formLogin.loginPage("/login").permitAll())
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    @Bean
    HttpSecurity httpSecurity() {
        return new HttpSecurity(authenticationManager);
    }

}
