package com.example.securityDemo.jwtconfig;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;


@Component
public class JwtUtils {


    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtExpirationTimeMS}")
    private long jwtExpirationTimeMS;

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;
    //getting token from header
    public String getJwtFromHeader(HttpServletRequest httpServletRequest){
        String bearerToken = httpServletRequest.getHeader("Authorization");

        logger.debug("Authorization :{} ", bearerToken);

        if(bearerToken != null){
            return bearerToken.substring(7 );
        }
        return  null;
    }

    //generating token from userName
    public String generateTokenFromUsername (UserDetails userDetails){
        String username = userDetails.getUsername();

        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date( new Date().getTime() + jwtExpirationTimeMS))
                .signWith(key())
                .compact();
    }

    //get username from token

    public String getUsernameFromJWTToken(String token){
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }


    //generating Signed Key

    public Key key(){
        return Keys.hmacShaKeyFor(
                Decoders.BASE64.decode(jwtSecret)
        );
    }

    //validate JWT Token

    public boolean validateJwtToken(String authToken){
        try{
            System.out.println("Validating");
            Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token : {}", e.getMessage());
        }
        catch (ExpiredJwtException e){
            logger.error("JWT token is expired : {}", e.getMessage());
        }
        catch (IllegalArgumentException e){
            logger.error("JWT claims String is empty: {}" , e.getMessage());
        }
        return  false;
    }


}
