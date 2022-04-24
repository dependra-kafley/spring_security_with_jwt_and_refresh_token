package com.depu.jwt.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * This is the class where we will check the successful authentication and atehntication and unsuccessful authentication
 * i.e. we will do what we need to do in case of successful authentication
 *
 * */

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
    }

    //When the users attempts to login this is the authentication method
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
    String username = request.getParameter("username");
    String password = request.getParameter("password");

    log.info("Username  is {} and password is{} ",username,password);
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username,password);
        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
    }

    //This is required for successful authentication
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        User user =(User) authentication.getPrincipal();
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());// this is the algorithm in production we need to pass the secret from somewhere else
        String access_token = JWT.create()
                .withSubject(user.getUsername()).// subject should be unique field which in this case in username
        withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 *1000)). // token will expire in 10 mins
                withIssuer(request.getRequestURI())// who has issued the token
                .withClaim("roles",user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList())).// mapping roles
                sign(algorithm);

        String refresh_token = JWT.create()
                .withSubject(user.getUsername()).// subject should be unique field which in this case in username
                        withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 *1000)). // token will expire in 30 can be made to expire on a day  mins
                        withIssuer(request.getRequestURI()).// who has issued the token
                        sign(algorithm);

        //sending the access token and refresh token in the header
        response.addHeader("access_token",access_token);
        response.addHeader("refresh_token",refresh_token);

        /***
         * passing in the response body
         *
         *  Map<String,String> tokens = new HashMap<>();
         *         tokens.put("access_token",access_token);
         *         tokens.put("refresh_token",refresh_token);
         *         response.setContentType(APPLICATION_JSON_VALUE);
         *         new ObjectMapper().writeValue(response.getOutputStream(),tokens);
         *
         */

    }
}
