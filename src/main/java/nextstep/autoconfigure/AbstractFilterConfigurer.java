package nextstep.autoconfigure;

import jakarta.annotation.Nullable;
import nextstep.security.access.RequestMatcher;

public abstract class AbstractFilterConfigurer<T extends AbstractFilterConfigurer<T>> implements SecurityConfigurer {
    private boolean permitAll = false;

    private boolean disable = false;

    @Override
    public void init(final HttpSecurity httpSecurity) {

    }

    @Override
    public void configure(final HttpSecurity httpSecurity) {
        if (disable) {
            return;
        }
        if (permitAll) {
            var authorizeHttpRequestsConfigurer = httpSecurity.getSharedObject(AuthorizeHttpRequestsConfigurer.class);
            var requestMatcher = getRequestMatcher();
            if (requestMatcher != null) {
                authorizeHttpRequestsConfigurer.requestMatchers(requestMatcher).permitAll();
            }
        }
        doConfigure(httpSecurity);
    }

    protected abstract void doConfigure(final HttpSecurity httpSecurity);

    @Nullable
    protected abstract RequestMatcher getRequestMatcher();

    public T permitAll() {
        this.permitAll = true;
        return (T) this;
    }

    public T disable() {
        this.disable = true;
        return (T) this;
    }


}
