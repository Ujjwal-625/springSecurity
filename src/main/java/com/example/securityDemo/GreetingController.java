package com.example.securityDemo;

import com.example.securityDemo.jwtconfig.JwtUtils;
import com.example.securityDemo.jwtconfig.LoginRequest;
import com.example.securityDemo.jwtconfig.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@EnableMethodSecurity
public class GreetingController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;

    @GetMapping("/hello")
    public String sayHello(){
        return "Hello";
    }

    @GetMapping("/helloAdmin")
    @PreAuthorize("hasRole('ADMIN')")
    public String sayHelloAdmin(){
        return "HelloAdmin";
    }


    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser (@RequestBody LoginRequest loginRequest){

        Authentication authentication;

        try{
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );
        }
        catch (AuthenticationException authenticationException){
            Map<String ,Object> map = new HashMap<>();
            map.put("message", "Bad Credentials");
            map.put("status", false);
            return new ResponseEntity<Object>(map , HttpStatus.UNAUTHORIZED);
        }

        // storing authentication in security context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        //getting userDetails
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        //generate the token from userName
        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(i-> i.getAuthority())
                .collect(Collectors.toList());

        LoginResponse loginResponse = new LoginResponse(
                userDetails.getUsername(),
                jwtToken,
                roles
        );

        return new ResponseEntity<>(loginResponse, HttpStatus.OK);
    }
}
