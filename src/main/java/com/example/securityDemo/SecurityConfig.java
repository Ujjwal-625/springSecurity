package com.example.securityDemo;


import com.example.securityDemo.jwtconfig.AuthEntryPointJwt;
import com.example.securityDemo.jwtconfig.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private DataSource dataSource;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler ;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter(){
        return new AuthTokenFilter();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/h2-console/**").permitAll()
                        .requestMatchers("/signin").permitAll()
                        .anyRequest().authenticated()
                )
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/h2-console/**","/signin")
                )
                .headers(headers -> headers
                        .frameOptions(frame -> frame.sameOrigin())
                );
        //creating stateless connection which is important for jwt .
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.formLogin(Customizer.withDefaults());
//        http.httpBasic(Customizer.withDefaults());


        //adding the exception handler for unauthorized req the one we created inintally (custome )
        http.exceptionHandling(
                exception-> exception.authenticationEntryPoint(unauthorizedHandler)
        );

        //adding my own filter before the default filter .
        http.addFilterBefore(authenticationJwtTokenFilter(),
                UsernamePasswordAuthenticationFilter.class);

            return http.build();
    }

    //we need to implement command line runner if we want to confirgure users before bean initialization
//    @Bean
//    UserDetailsService userDetailsService(){
//
//        UserDetails user1 = User.withUsername("user1").password( passwordEncoder().encode("user1") ).roles("USERS").build();
//        UserDetails admin = User.withUsername("admin").password(passwordEncoder().encode("admin") ).roles("ADMIN").build();
//
//        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
//
//        userDetailsManager.createUser(user1);
//        userDetailsManager.createUser(admin);
//
//        return userDetailsManager;
//
////        return new InMemoryUserDetailsManager(user1,user2);
//    }


    // here we are quickly creating the bean instead of returning it at the end as done previously
    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource){
        return new JdbcUserDetailsManager(dataSource);
    }

    // userDetailService bean is created on above method and being injected in the below method .
    @Bean
    public CommandLineRunner initData(){
        return  args->{

//            JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
            UserDetails user1 = User.withUsername("user1").password( passwordEncoder().encode("user1") ).roles("USERS").build();
            UserDetails admin = User.withUsername("admin").password(passwordEncoder().encode("admin") ).roles("ADMIN").build();

            JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);

            userDetailsManager.createUser(user1);
            userDetailsManager.createUser(admin);
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    //exposing this Authentication Manager as bean so that spring can inject it at runtime and we can use in controller to signin
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder){
        return builder.getAuthenticationManager();
    }
}
