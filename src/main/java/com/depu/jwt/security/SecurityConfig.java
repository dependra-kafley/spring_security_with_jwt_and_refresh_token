package com.depu.jwt.security;

import com.depu.jwt.filters.CustomAuthenticationFilter;
import com.depu.jwt.filters.CustomAuthorizationFilter;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * This class is used to override the security configuration It needs to ovverde the WebSecurityConfigurerAdapter
 * and have to have the annotations
 * @Configuration
 * @EnableWebSecurity
 *
 *
 *
 *
 * */
@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    /***
     * This calss lets spring know where to look for users from like jdbc or in memomry
     */

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        //User details lets spring know how we wants to load the user its provieded by sprign and we nedd to
        //override it and also we need to override the password encrypter
        // the load userName method needs to be overriden for the userdetails service and it is done in this application in
        //AppService class please check the class fro the implementation

        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);

    }

    /**
     * This method is uded to configure the https request like whether we ned to track of the login user using cookies
     * or the jwt we will configure the jwt here
     *
     * */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManagerBean());
        customAuthenticationFilter.setFilterProcessesUrl("/login");// to change the login url
        //http.csrf().disable();

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        // Note to be taken as the order needs to be maintained for the urls
        http.authorizeRequests().antMatchers("/login/**").permitAll();// allow all to the login page
        http.authorizeRequests().antMatchers("/adim/add/**").hasAnyAuthority("ROLE_ADMIN");// ALLOW only the users with admin acess
        http.authorizeRequests().antMatchers("/users/**").hasAnyAuthority("ROLE_USER");//Allow to the users
        http.authorizeRequests().anyRequest().authenticated(); // all request should be authenticated
        http.authorizeRequests().anyRequest().permitAll(); //permitting all the users to access
        http.addFilter(new CustomAuthenticationFilter(authenticationManagerBean())); //we check the authothentication through the filter here we are telling we have a filter
        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);// we need to add before filter so that it intercepts all the request



    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
