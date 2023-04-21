package shop.mtcoding.securityapp.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import shop.mtcoding.securityapp.core.jwt.JwtAuthorizationFilter;
import shop.mtcoding.securityapp.model.UserRepository;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
    private final UserRepository userRepository;


    @Bean
    BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    //패스워드 암호화 알고리즘 BCrypt-> 60Byte로 단방향 해시 암호화 +솔트

    @Bean
    //인증처리를 위해 빈으로 등록해 둬야한다.
    AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    // JWT 필터 등록이 필요하기 떄문에 내부클래스 구현해서 http.apply()로 등록
    public class CustomSecurityFilterManager extends AbstractHttpConfigurer<CustomSecurityFilterManager, HttpSecurity> {
        @Override
        public void configure(HttpSecurity builder) throws Exception {
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
            builder.addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository));
//            builder.addFilter(new JwtAuthorizationFilter(authenticationManager));
            //새로운 필터 추가

            super.configure(builder);
        }
    }


    //시큐리티의 설정 변경
    //: 기존의 extends WebMvcConfiguration에서 변경
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 1. CSRF 해제 : 타 사이트에서 악의적인 요청 - CSRF 공격 방어
        //: form 로그인 안쓰므로 CSRF 의미 없음
        http.csrf().disable(); // postman 접근해야 함!! - CSR 할때!!

        // 2. iframe 거부 : 보안성이 떨어지므로
        http.headers().frameOptions().disable();

        // 3. cors 재설정 : 동일 사이트에서 악의적인 요청 - XSS 공격 방어
        http.cors().configurationSource(configurationSource());

        // 4. jSessionId 사용 거부 : Session 메모리 영역은 사용 -> HTTP에 따른 JESSIONID를 쿠키에 저장하지 않도록
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // 5. form 로긴 해제 (UsernamePasswordAuthenticationFilter 비활성화)
        http.formLogin().disable();

        // 6. 로그인 인증창이 뜨지 않게 비활성화
        //: HTTP의 기본 인증방식인 BasicAuthentication 비활성화 -> 팝업 로그인
        http.httpBasic().disable();

        // 7. 커스텀 필터 적용 (시큐리티 필터 교환)
        //: JwtVerifyFilter 적용
        http.apply(new CustomSecurityFilterManager());

        // 8. 인증 실패 처리
        http.exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
            // checkpoint -> 예외핸들러 처리
            log.debug("디버그 : 인증 실패 : "+authException.getMessage());
            log.info("인포 : 인증 실패 : "+authException.getMessage());
            log.warn("워닝 : 인증 실패 : "+authException.getMessage());
            log.error("에러 : 인증 실패 : "+authException.getMessage());

            response.setContentType("text/plain; charset=utf-8");
            response.setStatus(401);
            response.getWriter().println("인증 실패");
        });

        // 10. 권한 실패 처리
        http.exceptionHandling().accessDeniedHandler((request, response, accessDeniedException) -> {
            // checkpoint -> 예외핸들러 처리
            log.debug("디버그 : 권한 실패 : "+accessDeniedException.getMessage());
            log.info("인포 : 권한 실패 : "+accessDeniedException.getMessage());
            log.warn("워닝 : 권한 실패 : "+accessDeniedException.getMessage());
            log.error("에러 : 권한 실패 : "+accessDeniedException.getMessage());

            response.setContentType("text/plain; charset=utf-8");
            response.setStatus(403);
            response.getWriter().println("권한 실패");
        });

        // 11. 인증, 권한 필터 설정
        http.authorizeRequests(
                authorize -> authorize.antMatchers("/users/**").authenticated()
                        .antMatchers("/manager/**")
                        .access("hasRole('ADMIN') or hasRole('MANAGER')")
                        .antMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().permitAll()
                );

        return http.build();
    }

    public CorsConfigurationSource configurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*"); // GET, POST, PUT, DELETE (Javascript 요청 허용)
        configuration.addAllowedOriginPattern("*"); // 모든 IP 주소 허용 (프론트 앤드 IP만 허용 react)
        configuration.setAllowCredentials(true); // 클라이언트에서 쿠키 요청 허용
        configuration.addExposedHeader("Authorization"); // 옛날에는 디폴트 였다. 지금은 아닙니다.
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
