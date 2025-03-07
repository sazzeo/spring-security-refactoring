package nextstep.autoconfigure;

import nextstep.oauth2.registration.ClientRegistrationRepository;
import nextstep.oauth2.web.OAuth2AuthorizationRequestRedirectFilter;
import nextstep.oauth2.web.OAuth2AuthorizedClientRepository;
import nextstep.oauth2.web.OAuth2LoginAuthenticationFilter;
import nextstep.security.authentication.AuthenticationManager;

public class OAuth2LoginConfigurer implements SecurityConfigurer {
    @Override
    public void init(final HttpSecurity httpSecurity) {

    }

    @Override
    public void configure(final HttpSecurity httpSecurity) {
        var repository = httpSecurity.getSharedObject(ClientRegistrationRepository.class);
        var redirectFilter = new OAuth2AuthorizationRequestRedirectFilter(repository);
        httpSecurity.addFilter(redirectFilter);
        var authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
        var filter = new OAuth2LoginAuthenticationFilter(repository, new OAuth2AuthorizedClientRepository(), authenticationManager);
        httpSecurity.addFilter(filter);
    }

}
