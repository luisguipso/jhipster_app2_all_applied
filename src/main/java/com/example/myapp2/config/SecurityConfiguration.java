package com.example.myapp2.config;

import com.example.myapp2.security.AuthoritiesConstants;
import com.example.myapp2.security.jwt.JWTConfigurer;
import com.example.myapp2.security.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.filter.CorsFilter;
import org.zalando.problem.spring.web.advice.security.SecurityProblemSupport;
import tech.jhipster.config.JHipsterProperties;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@Import(SecurityProblemSupport.class)
@Configuration
public class SecurityConfiguration {

    private final JHipsterProperties jHipsterProperties;

    private final TokenProvider tokenProvider;

    private final CorsFilter corsFilter;
    private final SecurityProblemSupport problemSupport;

    public SecurityConfiguration(
        TokenProvider tokenProvider,
        CorsFilter corsFilter,
        JHipsterProperties jHipsterProperties,
        SecurityProblemSupport problemSupport
    ) {
        this.tokenProvider = tokenProvider;
        this.corsFilter = corsFilter;
        this.problemSupport = problemSupport;
        this.jHipsterProperties = jHipsterProperties;
    }

    @Bean
    public org.springframework.security.crypto.password.PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/*").disable())
            .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling()
                .authenticationEntryPoint(problemSupport)
                .accessDeniedHandler(problemSupport)
        .and()
            .headers()
                .contentSecurityPolicy(jHipsterProperties.getSecurity().getContentSecurityPolicy())
            .and()
                .referrerPolicy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
            .and()
                .permissionsPolicy().policy("camera=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), sync-xhr=()")
            .and()
                .frameOptions().sameOrigin()
        .and()
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
            .authorizeRequests(ar -> ar.requestMatchers(HttpMethod.OPTIONS, "/*").permitAll()
            .requestMatchers("/app/*/*.js").permitAll()
            .requestMatchers("/app/*/*.html").permitAll()
            .requestMatchers("/i18n/*").permitAll()
            .requestMatchers("/content/*").permitAll()
            .requestMatchers("/swagger-ui/*").permitAll()
            .requestMatchers("/test/*").permitAll()
            .requestMatchers("/h2-console/*").permitAll()
            .requestMatchers("/api/authenticate").permitAll()
            .requestMatchers("/api/register").permitAll()
            .requestMatchers("/api/activate").permitAll()
            .requestMatchers("/api/account/reset-password/init").permitAll()
            .requestMatchers("/api/account/reset-password/finish").permitAll()
            .requestMatchers("/api/admin/*").hasAuthority(AuthoritiesConstants.ADMIN)
            .requestMatchers("/api/*").authenticated()
            .requestMatchers("/management/health").permitAll()
            .requestMatchers("/management/health/*").permitAll()
            .requestMatchers("/management/info").permitAll()
            .requestMatchers("/management/prometheus").permitAll()
            .requestMatchers("/management/*").hasAuthority(AuthoritiesConstants.ADMIN))
            .httpBasic()
        .and()
            .apply(securityConfigurerAdapter());
        return http.build();
        // @formatter:on
    }

    private JWTConfigurer securityConfigurerAdapter() {
        return new JWTConfigurer(tokenProvider);
    }
}
