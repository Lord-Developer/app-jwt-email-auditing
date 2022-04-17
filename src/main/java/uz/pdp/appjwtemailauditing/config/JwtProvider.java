package uz.pdp.appjwtemailauditing.config;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;
import uz.pdp.appjwtemailauditing.entity.Role;

import java.util.Date;
import java.util.Set;

@Component
public class JwtProvider {

    private final int EXPIRY_TIME = 1000 * 60 * 60 *24;
    private final String SECRET_KEY = "secret-key-for-jwt-token-772";

    public String generateToken(String username, Set<Role> roles){
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRY_TIME))
                .claim("roles", roles)
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                .compact();

    }

    public String getEmailFromToken(String token){
        try{
            String email = Jwts.parser()
                    .setSigningKey(SECRET_KEY)
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();
            return email;
        }catch (Exception ex){
            return null;
        }
    }
}
