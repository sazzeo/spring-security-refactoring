package nextstep.autoconfigure;

import jakarta.servlet.Filter;
import nextstep.oauth2.registration.ClientRegistrationRepository;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.config.DefaultSecurityFilterChain;
import nextstep.security.config.SecurityFilterChain;
import nextstep.security.context.SecurityContextHolderFilter;

import java.util.*;

public class HttpSecurity {

    private final LinkedHashMap<Class<? extends SecurityConfigurer>, SecurityConfigurer> configurers = new LinkedHashMap<>();
    private final List<Filter> filters = new ArrayList<>();
    private final Map<Class<?>, Object> sharedObjects = new HashMap<>();

    private final FilterOrderRegistration filterOrderRegistration = new FilterOrderRegistration();

    public HttpSecurity(final AuthenticationManager authenticationManager, final ClientRegistrationRepository clientRegistrationRepository) {
        this.setSharedObject(AuthenticationManager.class, authenticationManager);
        this.setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
    }

    public SecurityFilterChain build() {
        init();
        configure();
        sortFilter();
        return new DefaultSecurityFilterChain(filters);
    }


    public void addFilter(Filter filter) {
        filters.add(filter);
    }

    private void init() {
        for (SecurityConfigurer configurer : this.configurers.values()) {
            configurer.init(this);
        }
    }

    private void sortFilter() {
        this.filters.sort((filter1, filter2) -> filterOrderRegistration.getOrder(filter1) - filterOrderRegistration.getOrder(filter2));
    }

    private void configure() {
        filters.add(new SecurityContextHolderFilter());
        for (SecurityConfigurer configurer : this.configurers.values()) {
            configurer.configure(this);
        }
    }

    private <T extends SecurityConfigurer> T getOrApply(T configurer) {
        var clazz = configurer.getClass();
        var existedConfigured = this.configurers.get(clazz);
        if (existedConfigured != null) {
            return (T) existedConfigured;
        }
        this.configurers.put(clazz, configurer);
        return configurer;
    }

    public <T> T getSharedObject(final Class<T> clazz) {
        Object obj = sharedObjects.get(clazz);
        return (T) obj;
    }

    public <T> void setSharedObject(final Class<T> clazz, T object) {
        sharedObjects.put(clazz, object);
    }

    public HttpSecurity csrf() {
        return this;
    }

    public HttpSecurity formLogin(final Customizer<FormLoginConfigurer> customizer) {
        customizer.customize(getOrApply(new FormLoginConfigurer()));
        return this;
    }

    public HttpSecurity httpBasic(final Customizer<HttpBasicConfigurer> customizer) {
        customizer.customize(getOrApply(new HttpBasicConfigurer()));
        return this;
    }

    public HttpSecurity authorizeHttpRequests(final Customizer<AuthorizeHttpRequestsConfigurer> customizer) {
        customizer.customize(getOrApply(new AuthorizeHttpRequestsConfigurer()));
        return this;
    }

    public HttpSecurity oAuth2Login(final Customizer<OAuth2LoginConfigurer> customizer) {
        customizer.customize(getOrApply(new OAuth2LoginConfigurer()));
        return this;
    }
}
