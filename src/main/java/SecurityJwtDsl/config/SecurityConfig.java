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
          .cors(withDefaults())
          .csrf(csrf -> {
              // CsrfToken 쿠키 저장소 생성 (HttpOnly=false)
              CookieCsrfTokenRepository repo = CookieCsrfTokenRepository.withHttpOnlyFalse();
              // deprecated setSecure 대신 커스터마이저로 Secure, SameSite 설정
              repo.setCookieCustomizer(builder ->
                  builder
                    .secure(true)                 // HTTPS 전용 전송
                    .sameSite("Strict")           // SameSite=Strict
              );
              csrf
                .csrfTokenRepository(repo)
                .ignoringRequestMatchers( // 밑의 URL의 해당 메소드로 들어온 요청은 토큰 검사 제외(프로젝트시 수정 필요)
                  new AntPathRequestMatcher("/member/login", "POST"), 
                  new AntPathRequestMatcher("/member/logout", "POST")
                );
          })
            .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션 안쓸거라 세션 안쓴다고 명시함
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**", "/swagger-ui/**", "/v3/api-docs/**").permitAll() // 안에 들어있는 URL로 들어온 요청에 대해선 인증검사 안함(프로젝트시 수정 필요)
                .anyRequest().authenticated()
            )
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(customAuthenticationEntryPoint)
                .accessDeniedHandler(customAccessDeniedHandler)
            )
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of(
            "http://localhost:3000"                  // 허용할 프론트 주소, 실 배포중에는 실제 도메인 작성 (프로젝트시 수정 필요)
        ));
        config.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));
        config.setAllowedHeaders(List.of("*"));         // 모든 헤더 허용
        config.setAllowCredentials(true);               // 쿠키, 인증정보 허용

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config); 
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