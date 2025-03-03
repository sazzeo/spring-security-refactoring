package nextstep.autoconfigure;

import jakarta.servlet.Filter;
import nextstep.security.config.DefaultSecurityFilterChain;
import nextstep.security.config.SecurityFilterChain;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

public class HttpSecurity {

    private final LinkedHashMap<Class<? extends SecurityConfigurer>, SecurityConfigurer> configurers = new LinkedHashMap<>();
    private List<Filter> filters = new ArrayList<>();

    public SecurityFilterChain build() {
        init();
        configure();
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

    private void configure() {
        for (SecurityConfigurer configurer : this.configurers.values()) {
            configurer.configure(this);
        }
    }

    private SecurityConfigurer getOrApply(SecurityConfigurer configurer) {
        this.configurers.put(clazz, configurer);
        return configurer;
    }

    public HttpSecurity csrf() {
        return this;
    }

    public HttpSecurity formLogin(final Customizer<FormLoginConfigurer> customizer) {
        FormLoginConfigurer formLoginConfigurer = new FormLoginConfigurer();
        formLoginConfigurer.init(this);
        customizer.customize(formLoginConfigurer);
        formLoginConfigurer.configure(this);
        return this;
    }
}
