package SecurityJwtDsl.config;

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import SecurityJwtDsl.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final JwtAuthenticationFilter jwtAuthenticationFilter;
	private final AuthenticationEntryPoint customAuthenticationEntryPoint;
	private final AccessDeniedHandler customAccessDeniedHandler;

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		http
			.cors(withDefaults()) // 기본 설정에 따르겠다는 의미.
			// 밑에서 CorsConfigurationSource 설정 값을 @Bean으로 등록했으니 그것이 사용됨
			.csrf(csrf -> {
					CookieCsrfTokenRepository repo = new CookieCsrfTokenRepository();// CsrfToken 쿠키 저장소 생성 (기본 HttpOnly=true, 필요시 커스터마이징 가능)
					repo.setCookieCustomizer(builder ->
						builder
							.secure(false)  // HTTPS 연결일때만 브라우저가 서버 전송 가능, 현재는 로컬 개발이니 false로 설정, 실 배포시 true로 변경해야함
							.sameSite("Strict") // 다른 사이트의 요청에선 쿠키를 보내지 않게 브라우저에게 명령
					);
					csrf.csrfTokenRepository(repo).ignoringRequestMatchers( 
							// 밑의 URL의 해당 메소드로 들어온 요청은 CSRF 토큰 검사 제외(프로젝트시 수정 필요)
							new AntPathRequestMatcher("/member/login", "POST"),
							new AntPathRequestMatcher("/member/logout", "POST"));
				})
			.sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션 안쓸거라 세션 안쓴다고 명시함
			.authorizeHttpRequests(
					auth -> auth.requestMatchers("/api/auth/**", "/swagger-ui/**", "/v3/api-docs/**").permitAll() 
					// 안에 들어있는 URL로 들어온 요청에 대해선 인증검사안함(프로젝트시	수정필요) 
					// 여기서 수행하는 인증 절차는 스프링이 제공하는 각 filter 및 아래에 명시한 jwtAuthenticationFilter등이 포함됨
								.anyRequest().authenticated()
								 // 위에 명시된 URL을 제외한 어떠한 요청도 인증검사 수행
				)
				.exceptionHandling(ex -> ex.authenticationEntryPoint(customAuthenticationEntryPoint)
						.accessDeniedHandler(customAccessDeniedHandler))
				.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
		// UsernamePasswordAuthenticationFilter.class 보다 앞서서 jwtAuthenticationFilter 수행
		return http.build();
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowedOrigins(List.of("http://localhost:3000")); // 허용할 프론트 주소, 실 배포중에는 실제 도메인 작성 (프로젝트시 수정 필요)
		config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS")); // 이 메소드만 허용
		config.setAllowedHeaders(List.of("Content-Type", "Authorization")); // 헤더 정보 중, Content-Type(요청 데이터 형식)과 Authorization(JWT 토큰) 헤더만 허용
		// 이 모든 허용은 모두 and로 3가지 조건 모두 만족 시 허용
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", config); // 모든 경로에 대해 위 cors 정책을 적용
		return source;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}
}