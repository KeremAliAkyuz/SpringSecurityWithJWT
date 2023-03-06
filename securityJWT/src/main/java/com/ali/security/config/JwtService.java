package com.ali.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "33743677397A24432646294A404E635266546A576E5A7234753778214125442A";//all keys generatordan 256 bit seçeneğiyle çıkarttım

    public String extractUsername(String token) {
        return extractClaim(token,Claims::getSubject); //Subject user'ın emailidir.
    }

    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration); //Expiration date'i extract eder
    }

    //extra claimler olmadan JWT tokeni oluşturma
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }


    //extra claimler ile JWT tokeni oluşturma
    public String generateToken(Map<String ,Object> extraClaims, UserDetails userDetails){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())//subject username veya email olmalı
                .setIssuedAt(new Date(System.currentTimeMillis()))//claim ne zaman oluşturuldu
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))//ne zaman bitecek
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) //hangi key'i sign in olmak için kullnamak istiyosun
                .compact();
    }

    //token ait olması gereken user'a mı ait?
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    //token'in tarihi geçti mi?
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }




    //İstediğimiz bir claimi ayrıştırır
    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    //token içinde bulunan tüm claimleri extract eden method
    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder() //builder'ı ayrıştırmak için kullanılır
                .setSigningKey(getSignInKey())//token'i decode etmek için lazımdır.
                .build()
                .parseClaimsJws(token) //token'i parse eder
                .getBody(); //bununla beraber token içindeki tüm claimleri alırız
    }

    //Token base64 şeklinde bulunur.hmacSha256 algoritması sayesinde secret key ile koruduğumuz tokeni extract ederiz.
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
