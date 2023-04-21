package shop.mtcoding.securityapp.core.jwt;

import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;
import shop.mtcoding.securityapp.core.auth.MyUserDetails;
import shop.mtcoding.securityapp.dto.ResponseDTO;
import shop.mtcoding.securityapp.model.User;
import shop.mtcoding.securityapp.model.UserRepository;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 모든 주소에서 발동
@Slf4j
@Component
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    //필터를 등록안하는게 좋지만, 빈으로 등록해서
    private UserRepository userRepository;
    private AuthenticationManager authenticationManager;
//    public JwtAuthorizationFilter(AuthenticationManager authenticationManager){
//        super(authenticationManager);
//        this.authenticationManager=authenticationManager;
//    }
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.authenticationManager=authenticationManager;
        this.userRepository=userRepository;

        //강제 인증 처리
        UsernamePasswordAuthenticationToken token= new UsernamePasswordAuthenticationToken(null, null, null);
        authenticationManager.authenticate(token);  //AuthenticationProvider -> UserDetailsService의 loadByUsername 강제 호출
        //loadByUsername는 SecurityContextHolder에 강제로 Authentication 객체를 주입한다.
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String prefixJwt = request.getHeader(MyJwtProvider.HEADER);

        if (prefixJwt == null) {
            //토큰 없으면 거부하기 위해서는 여기서

            //토큰 있으면 들어오게 하고
            //없으면 거부 해야함
            chain.doFilter(request, response);
            return;
        }

        String jwt = prefixJwt.replace(MyJwtProvider.TOKEN_PREFIX, "");
        try {
            DecodedJWT decodedJWT = MyJwtProvider.verify(jwt);
            //토큰 검증 성공시

            Long id = decodedJWT.getClaim("id").asLong();
            String username = decodedJWT.getClaim("username").asString();
            String role = decodedJWT.getClaim("role").asString();

            //UserDetailsService를 타지 않고 강제로 Authentication 객체를 만들어서 주입한다. -> 세션에 주입한다는 것
            //: 여기서 Username을 전달해야 유저네임을 찾을 수 있다.
            //페이로드 -> JWT가 확장성이 좋은 이유
            User user = User.builder().id(id).username(username).role(role).build();
            MyUserDetails myUserDetails = new MyUserDetails(user);
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(
                            myUserDetails,
                            myUserDetails.getPassword(),    //null
                            myUserDetails.getAuthorities()
                    );
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (SignatureVerificationException sve) {
            log.error("토큰 검증 실패");
        } catch (TokenExpiredException tee) {
            log.error("토큰 만료됨");
        } finally {
            chain.doFilter(request, response);
        }
    }
}
