package com.ali.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader=request.getHeader("Authorization"); //jwt header'da olur bu yüzden request'ten header'ı çektik ve ona Authorization ismini verdik.
        final String jwt;
        final String userEmail;

        if(authHeader == null ||!authHeader.startsWith("Bearer")){ //eğer headerımız null'sa veya Bearer ile başlamıyorsa FilterChain'deki diğer filter'a geç
            filterChain.doFilter(request,response); //Check etmiş olduk.
            return;
        }
        //header'dan jwt token'i çıkartalım
        jwt = authHeader.substring(7); //7. indexten başlamamızın sebebi "Bearer " stringinin boşluk ile beraber 7 karakter içermesi
        //userEmailini de jwt token'den çıkartalım
        userEmail = jwtService.extractUsername(jwt);//userEmaili çıkarmak için jwtService adında bir class oluşturdum
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){//user authenticated olmadığını kontol eder.
        //user connected değil ise user'ı database'den çağırıp tokenden extract ettiğimiz user'la aynı mı konrol ederiz
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if(jwtService.isTokenValid(jwt, userDetails)){

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );//tokenimiz geçerli ise oluşturuğumuz UsernamePasswordAuthenticationToken tokenini security context holder'a kaydederiz.

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); //daha fazla detay vermek için

                SecurityContextHolder.getContext().setAuthentication(authToken);//security context holder'a kaydettik
            }
        }
        filterChain.doFilter(request,response); //diğer filter'a geçmesi için bunu yazmayı unutma!
    }
}
