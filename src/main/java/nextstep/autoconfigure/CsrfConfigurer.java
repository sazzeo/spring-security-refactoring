package nextstep.autoconfigure;

import jakarta.annotation.Nullable;
import nextstep.security.access.NegatedRequestMatcher;
import nextstep.security.access.OrRequestMatcher;
import nextstep.security.access.PathRequestMatcher;
import nextstep.security.access.RequestMatcher;
import nextstep.security.csrf.CsrfFilter;
import nextstep.security.csrf.CsrfTokenRepository;
import nextstep.security.csrf.DefaultCsrfRequestMatcher;
import nextstep.security.csrf.HttpSessionCsrfTokenRepository;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CsrfConfigurer extends AbstractFilterConfigurer<CsrfConfigurer> {

    private List<String> ignoringRequestUrl;
    private CsrfTokenRepository DEFAULT_CSRF_REPOSITORY = new HttpSessionCsrfTokenRepository();

    @Override
    protected void doConfigure(final HttpSecurity httpSecurity) {
        var filter = new CsrfFilter(DEFAULT_CSRF_REPOSITORY);
        RequestMatcher ignoringRequestMatchers = createIgnoringRequestMatchers();
        if (ignoringRequestMatchers != null) {
            filter.setRequestMatcher(ignoringRequestMatchers);
        }
        httpSecurity.addFilter(filter);
    }

    @Override
    protected RequestMatcher getRequestMatcher() {
        return null;
    }

    @Nullable
    private RequestMatcher createIgnoringRequestMatchers() {
        if (ignoringRequestUrl == null || ignoringRequestUrl.isEmpty()) {
            return null;
        }
        var requestMatchers = new ArrayList<RequestMatcher>(ignoringRequestUrl.stream()
                .map(PathRequestMatcher::new)
                .toList());
        //TODO: 여기 수정 필요
        return new OrRequestMatcher(List.of(new NegatedRequestMatcher(new OrRequestMatcher(requestMatchers)), new DefaultCsrfRequestMatcher()));
    }

    public CsrfConfigurer ignoringRequestMatchers(String... requestUrls) {
        this.ignoringRequestUrl = Arrays.stream(requestUrls).toList();
        return this;
    }

}
