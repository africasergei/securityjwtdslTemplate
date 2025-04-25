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
          .cors(withDefaults())  // 밑에서 CorsConfigurationSource 설정 했으니 기본값 쓰겠다는 의미
          .csrf(config -> config.disable()) // 쿠키 기반 인증이 아니니 csrf 방어 하지 않음
          .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션 안쓸거라 세션 안쓴다고 명시함
          .authorizeHttpRequests(auth -> auth
        		  .requestMatchers("/api/auth/**", "/swagger-ui/**", "/v3/api-docs/**").permitAll() // 안에 들어있는 URL로 들어온 요청에 대해선 인증검사 안함(프로젝트시 수정 필요)
        		  .anyRequest().authenticated() // 위에 명시된 URL을 제외한 어떠한 요청도 인증검사 수행
            )
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(customAuthenticationEntryPoint)
                .accessDeniedHandler(customAccessDeniedHandler)
            )
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class); 
    	 // UsernamePasswordAuthenticationFilter.class 보다 앞서서 jwtAuthenticationFilter 수행
        return http.build();
    }
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of(
            "http://localhost:3000"                  // 허용할 프론트 주소, 실 배포중에는 실제 도메인 작성 (프로젝트시 수정 필요)
        ));
        config.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));
        config.setAllowedHeaders(List.of("Content-Type", "Authorization"));         // 바디의 형태, jwt 정보를 받아야하니 이 두개의 헤더만 허용

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