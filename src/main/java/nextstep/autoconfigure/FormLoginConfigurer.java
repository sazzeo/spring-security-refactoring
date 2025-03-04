package nextstep.autoconfigure;

import nextstep.security.access.MvcRequestMatcher;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.http.HttpMethod;

public class FormLoginConfigurer implements SecurityConfigurer {

    private String loginUrl = "/login";

    private boolean permitAll = false;

    private boolean disable = false;

    public FormLoginConfigurer() {
    }

    @Override
    public void init(final HttpSecurity httpSecurity) {

    }

    @Override
    public void configure(final HttpSecurity httpSecurity) {
        if (disable) {
            return;
        }
        var filter = new UsernamePasswordAuthenticationFilter(httpSecurity.getSharedObject(AuthenticationManager.class));
        if (permitAll) {
            //TODO
        }
        filter.setRequestMatcher(new MvcRequestMatcher(HttpMethod.POST, loginUrl));
        httpSecurity.addFilter(filter);
    }

    public FormLoginConfigurer loginPage(final String loginUrl) {
        this.loginUrl = loginUrl;
        return this;
    }

    public FormLoginConfigurer permitAll() {
        this.permitAll = true;
        return this;
    }

    public FormLoginConfigurer disable() {
        this.disable = true;
        return this;
    }

}
