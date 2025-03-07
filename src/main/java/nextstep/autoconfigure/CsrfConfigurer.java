package nextstep.autoconfigure;

import nextstep.security.access.RequestMatcher;

public class CsrfConfigurer extends AbstractFilterConfigurer<CsrfConfigurer> {
    @Override
    protected void doConfigure(final HttpSecurity httpSecurity) {

    }

    @Override
    protected RequestMatcher getRequestMatcher() {
        return null;
    }

}
