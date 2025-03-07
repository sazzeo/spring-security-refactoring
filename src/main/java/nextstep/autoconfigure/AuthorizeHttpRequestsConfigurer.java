package nextstep.autoconfigure;

import jakarta.servlet.http.HttpServletRequest;
import nextstep.security.access.*;
import nextstep.security.access.hierarchicalroles.RoleHierarchyImpl;
import nextstep.security.authorization.*;

import java.util.ArrayList;
import java.util.List;

public class AuthorizeHttpRequestsConfigurer implements SecurityConfigurer {

    private final List<RequestMatcherEntry<AuthorizationManager<HttpServletRequest>>> requestMatcherEntries = new ArrayList<>();

    @Override
    public void init(final HttpSecurity httpSecurity) {

    }

    @Override
    public void configure(final HttpSecurity httpSecurity) {
        var authorizationManager = new RequestMatcherDelegatingAuthorizationManager(requestMatcherEntries);
        var filter = new AuthorizationFilter(authorizationManager);
        httpSecurity.addFilter(filter);
    }

    public AuthorizeBuilder requestMatchers(final RequestMatcher requestMatcher) {
        return new AuthorizeBuilder(this, requestMatcher);
    }

    public AuthorizeBuilder requestMatchers(final String path) {
        return new AuthorizeBuilder(this, new PathRequestMatcher(path));
    }

    public AuthorizeBuilder anyRequest() {
        return new AuthorizeBuilder(this, null);
    }


    private void addRequestMatcherEntry(final RequestMatcher requestMatcher, final AuthorizationManager<HttpServletRequest> authorizationManager) {
        requestMatcherEntries.add(new RequestMatcherEntry<>(requestMatcher, authorizationManager));
    }

    public static class AuthorizeBuilder {
        private final AuthorizeHttpRequestsConfigurer configurer;
        private final RequestMatcher requestMatcher;

        public AuthorizeBuilder(final AuthorizeHttpRequestsConfigurer configurer, final RequestMatcher requestMatcher) {
            this.configurer = configurer;
            this.requestMatcher = requestMatcher;
        }

        public AuthorizeHttpRequestsConfigurer permitAll() {
            configurer.addRequestMatcherEntry(requestMatcher, new PermitAllAuthorizationManager<>());
            return this.configurer;
        }

        public AuthorizeHttpRequestsConfigurer authenticated() {
            configurer.addRequestMatcherEntry(AnyRequestMatcher.INSTANCE, new AuthenticatedAuthorizationManager<>());
            return this.configurer;
        }

        public AuthorizeHttpRequestsConfigurer hasAuthority(String authority) {
            //TODO: 주입받도록 변경
            var roleHierarchy = RoleHierarchyImpl.with()
                    .role("ADMIN").implies("USER")
                    .build();
            configurer.addRequestMatcherEntry(requestMatcher, new AuthorityAuthorizationManager<>(
                    roleHierarchy,
                    "ADMIN"));
            return this.configurer;
        }

    }


}
