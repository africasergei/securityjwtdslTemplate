package SecurityJwtDsl.jwt;

import java.security.Key;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;

@Component
public class TokenProvider {

	private final Key key;

	public TokenProvider(@Value("${jwt.secret}") String secret) {
		this.key = Keys.hmacShaKeyFor(secret.getBytes());
	}

	public String createToken(String email, List<String> roles, long tokenValidity) { // 고유 식별자, 권한, 만료시간(프로젝트때 수정)
	    Date now = new Date();
	    Date expiry = new Date(now.getTime() + tokenValidity);

	    return Jwts.builder()
	        .setSubject(email) // email은 여전히 subject로
	        .claim("roles", roles) // roles는 커스텀 claim으로 추가
	        .setIssuedAt(now)
	        .setExpiration(expiry)
	        .signWith(key, SignatureAlgorithm.HS256)
	        .compact();
	}

	public boolean validateToken(String token) {
		try {
			Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
			return true;
		} catch (SecurityException | MalformedJwtException | ExpiredJwtException | UnsupportedJwtException
				| IllegalArgumentException e) {
			return false;
		}
	}

	public String getEmailFromToken(String token) {
		return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().getSubject();
	}
}