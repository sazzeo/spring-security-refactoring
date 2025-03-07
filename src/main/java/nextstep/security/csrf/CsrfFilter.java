package nextstep.security.csrf;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.security.access.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class CsrfFilter extends OncePerRequestFilter {
    private final CsrfTokenRepository csrfTokenRepository;
    private final RequestMatcher requestMatcher;
    private final AccessDeniedHandler accessDeniedHandler;

    public CsrfFilter(final CsrfTokenRepository csrfTokenRepository, final RequestMatcher requestMatcher, final AccessDeniedHandler accessDeniedHandler) {
        this.csrfTokenRepository = csrfTokenRepository;
        this.requestMatcher = requestMatcher;
        this.accessDeniedHandler = accessDeniedHandler;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var csrfToken = csrfTokenRepository.loadToken(request);
        if (csrfToken == null) {
            csrfToken = csrfTokenRepository.generateToken(request);
            csrfTokenRepository.saveToken(csrfToken, request, response);
        }
        request.setAttribute(csrfToken.getParameterName(), csrfToken);
        if (!requestMatcher.matches(request)) {
            doFilter(request, response, filterChain);
            return;
        }


    }
}
