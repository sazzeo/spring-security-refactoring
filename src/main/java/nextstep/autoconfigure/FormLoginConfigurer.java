package nextstep.autoconfigure;

import nextstep.security.access.MvcRequestMatcher;
import nextstep.security.access.OrRequestMatcher;
import nextstep.security.access.PathRequestMatcher;
import nextstep.security.access.RequestMatcher;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.UsernamePasswordAuthenticationFilter;
import nextstep.security.context.SecurityContextRepository;
import org.springframework.http.HttpMethod;

import java.util.List;

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
        var contextRepository = httpSecurity.getSharedObject(SecurityContextRepository.class);
        if(contextRepository != null) {
            filter.setSecurityContextRepository(contextRepository);
        }
        httpSecurity.addFilter(filter);
    }

    @Override
    protected RequestMatcher getRequestMatcher() {
        return new OrRequestMatcher(
                List.of(new MvcRequestMatcher(HttpMethod.GET, loginUrl),
                        new MvcRequestMatcher(HttpMethod.POST, loginUrl)
                ));
    }

    public FormLoginConfigurer loginPage(final String loginUrl) {
        this.loginUrl = loginUrl;
        return this;
    }

}
