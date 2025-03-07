package nextstep.autoconfigure;

import nextstep.security.access.MvcRequestMatcher;
import nextstep.security.access.PathRequestMatcher;
import nextstep.security.access.RequestMatcher;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.http.HttpMethod;

public class FormLoginConfigurer extends AbstractFilterConfigurer<FormLoginConfigurer> {

    private String loginUrl = "/login";


    public FormLoginConfigurer() {
    }

    @Override
    public void init(final HttpSecurity httpSecurity) {

    }

    @Override
    protected void doConfigure(final HttpSecurity httpSecurity) {
        var filter = new UsernamePasswordAuthenticationFilter(httpSecurity.getSharedObject(AuthenticationManager.class));
        filter.setRequestMatcher(new MvcRequestMatcher(HttpMethod.POST, loginUrl));
        httpSecurity.addFilter(filter);
    }

    @Override
    protected RequestMatcher getRequestMatcher() {
        return new PathRequestMatcher(loginUrl);
    }

    public FormLoginConfigurer loginPage(final String loginUrl) {
        this.loginUrl = loginUrl;
        return this;
    }

}
