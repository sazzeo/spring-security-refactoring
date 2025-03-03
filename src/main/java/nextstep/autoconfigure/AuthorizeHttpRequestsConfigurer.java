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

    public AuthorizeBuilder requestMatchers(final String path) {
        return new AuthorizeBuilder(this, path);
    }

    public AuthorizeBuilder anyRequest() {
        return new AuthorizeBuilder(this, null);
    }


    private void addRequestMatcherEntry(RequestMatcher requestMatcher, AuthorizationManager<HttpServletRequest> authorizationManager) {
        requestMatcherEntries.add(new RequestMatcherEntry<>(requestMatcher, authorizationManager));
    }

    public static class AuthorizeBuilder {
        private final AuthorizeHttpRequestsConfigurer configurer;
        private final String path;

        public AuthorizeBuilder(final AuthorizeHttpRequestsConfigurer configurer, final String path) {
            this.configurer = configurer;
            this.path = path;
        }

        public AuthorizeHttpRequestsConfigurer permitAll() {
            configurer.addRequestMatcherEntry(new PathRequestMatcher(path), new PermitAllAuthorizationManager<>());
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
            configurer.addRequestMatcherEntry(new PathRequestMatcher(path), new AuthorityAuthorizationManager<>(
                    roleHierarchy,
                    "ADMIN"));
            return this.configurer;
        }

    }


}
