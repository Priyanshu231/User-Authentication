package com.bej.authenticationservice.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
public class JwtFilter extends GenericFilterBean {
    //     this method will check the token generated or not ,if generated then validate the token(check token is valid or invalid)
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
//        convert the servletRequest,servletResponse into http
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
//        fetch the response data.
        ServletOutputStream outputStream = httpServletResponse.getOutputStream();
//        expects the token to come from the header.
        String authHeader = httpServletRequest.getHeader("Authorization");
        if (authHeader==null || !authHeader.startsWith("Bearer")) {
//        if token is not coming then get the response status as UNAUTHORIZED.
            httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
        else {
//            extract the token from the header.
            String jwtToken = authHeader.substring(7); // Bearer ==> 6+1 since token begin with Bearer
//            token validation ( for token validation the key is required created in JwtSecurityTokenGeneratorImpl).
            String userName = Jwts.parser().setSigningKey("securitykey").parseClaimsJws(jwtToken).getBody().getSubject();
//            if token generated then it will validate the token and set the userName/email.
            httpServletRequest.setAttribute("userName",userName);
//            pass the claim in the request or if token is validate then pass the claim in the request.
            filterChain.doFilter(servletRequest,servletResponse); // forward request to some filter , controller.
        }
    }
}