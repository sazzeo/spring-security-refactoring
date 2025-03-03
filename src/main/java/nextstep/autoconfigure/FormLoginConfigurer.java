package nextstep.autoconfigure;

import nextstep.security.authentication.UsernamePasswordAuthenticationFilter;

public class FormLoginConfigurer implements SecurityConfigurer {

    private UsernamePasswordAuthenticationFilter filter;

    public FormLoginConfigurer() {

    }

    @Override
    public void init(final HttpSecurity httpSecurity) {

    }

    @Override
    public void configure(final HttpSecurity httpSecurity) {

        var filter = new UsernamePasswordAuthenticationFilter();




        httpSecurity.addFilter(filter);
    }

    public Object loginPage(final String loginUrl) {

    }
}
