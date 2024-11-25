package com.api.gateway.jwt;



import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtHelper {
	

    //requirement :
	private static final long JWT_TOKEN_VALIDITY = 30 * 24 * 60 * 60;

    //    public static final long JWT_TOKEN_VALIDITY =  60;
    private String secret = "afafasfafafasfasfasfafacasdasfasxASFACASDFACASDFASFASFDAFASFASDAADSCSDFADCVSGCFVADXCcadwavfsfarvf";
    
    //retrieve username from jwt token
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    //retrieve expiration date from jwt token
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    //for retrieveing any information from token we will need the secret key
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    //check if the token has expired
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    public String generateToken(String phoneNumber) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("phoneNumber", phoneNumber);
        
        return doGenerateToken(claims, phoneNumber);
    }

    private String doGenerateToken(Map<String, Object> claims, String subject) {
        Date expirationDate = new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000);
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }


 // Validate token with phone number and OTP
    public Boolean validateToken(String token, String phoneNumber) {
        final String username = getUsernameFromToken(token);
        final String storedPhoneNumber = getPhoneNumberFromToken(token);
       

        // Check if the username (phone number) and OTP match the provided values
        return (username.equals(phoneNumber) && storedPhoneNumber.equals(phoneNumber) 
                && !isTokenExpired(token));
    }

    public String getPhoneNumberFromToken(String token) {
        return getClaimFromToken(token, claims -> (String) claims.get("phoneNumber"));
    }

    public int getOtpFromToken(String token) {
    	Integer otpClaim = getClaimFromToken(token, claims -> (Integer) claims.get("otp"));
        return otpClaim != null ? otpClaim.intValue() : 0;
    }
   
}

