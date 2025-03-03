package nextstep.autoconfigure;

import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.BasicAuthenticationFilter;

public class HttpBasicConfigurer implements SecurityConfigurer {
    @Override
    public void init(final HttpSecurity httpSecurity) {

    }

    @Override
    public void configure(final HttpSecurity httpSecurity) {
        var filter = new BasicAuthenticationFilter(httpSecurity.getSharedObject(AuthenticationManager.class));
        httpSecurity.addFilter(filter);
    }

}
