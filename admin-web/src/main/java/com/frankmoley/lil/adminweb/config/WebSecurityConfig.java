package com.frankmoley.lil.adminweb.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.ContextSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.ldap.userdetails.LdapUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * In Spring boot 3 WebSecurityConfigurerAdapter is no longer available
 * @see <a href="https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter">Spring Security without the WebSecurityConfigurerAdapter</a>
 */

@Configuration
@EnableWebSecurity
public class WebSecurityConfig{

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authz -> authz
                        .requestMatchers("/", "/login").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> {
                    form.loginPage("/login").permitAll();
                    form.failureUrl("/login?error");
                })
                .logout(httpSecurityLogoutConfigurer -> {
                            httpSecurityLogoutConfigurer.clearAuthentication(true);
                            httpSecurityLogoutConfigurer.invalidateHttpSession(true);
                            httpSecurityLogoutConfigurer.logoutSuccessUrl("/login?logout");
                        }
                );
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(ContextSource context) {
        return new LdapUserDetailsManager(context);
    }

    @Autowired
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder
                .ldapAuthentication()
                .userDnPatterns("uid={0},ou=people")
                .groupSearchBase("ou=groups")
                .contextSource()
                .url("ldap://localhost:8389/dc=landon,dc=org")
                .and()
                .passwordCompare()
                .passwordEncoder(new BCryptPasswordEncoder())
                .passwordAttribute("userPassword");
    }

}
