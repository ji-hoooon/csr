package shop.mtcoding.securityapp.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import shop.mtcoding.securityapp.core.jwt.MyJwtProvider;
import shop.mtcoding.securityapp.dto.UserRequest;
import shop.mtcoding.securityapp.dto.UserResponse;
import shop.mtcoding.securityapp.model.User;
import shop.mtcoding.securityapp.model.UserRepository;

import java.util.Optional;

@RequiredArgsConstructor
@Service
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @Value("${meta.name}")
    private String secret;

    /**
     *  1. 트랜잭션 관리
     *  2. 영속성 객체 변경감지
     *  3. RequestDTO 요청받기
     *  4. 비지니스 로직 처리하기
     *  5. ResponseDTO 응답하기
     */
    @Transactional
    public UserResponse.JoinDto 회원가입(UserRequest.JoinDTO joinDTO){
        // select
        String rawPassword = joinDTO.getPassword();
        String encPassword = passwordEncoder.encode(rawPassword); // 60Byte
        joinDTO.setPassword(encPassword);
        User userPS = userRepository.save(joinDTO.toEntity());
        return new UserResponse.JoinDto(userPS);
    }

    public String 로그인(UserRequest.LoginDTO loginDTO) {
        Optional<User> userOP = userRepository.findByUsername(loginDTO.getUsername());
        //UserDetailsService에서 하던 로직
        if(userOP.isPresent()){
            User userPS = userOP.get();
            //passwordEncoder.matches 메서드로 로우 패스워드와 인코딩된 패스워드를 비교 가능
            if(passwordEncoder.matches(loginDTO.getPassword(), userPS.getPassword())){
                String jwt = MyJwtProvider.create(userPS);
                return jwt;
                //String 리턴해서 컨트롤러에서 헤더(Authentication)에 응답해주면 끝
            }
            throw new RuntimeException("패스워드 틀렸어");
        }else{
            throw new RuntimeException("유저네임 없어");
        }
    }
}
