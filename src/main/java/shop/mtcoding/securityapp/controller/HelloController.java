package shop.mtcoding.securityapp.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import shop.mtcoding.securityapp.core.auth.MyUserDetails;
import shop.mtcoding.securityapp.core.jwt.MyJwtProvider;
import shop.mtcoding.securityapp.dto.ResponseDTO;
import shop.mtcoding.securityapp.dto.UserRequest;
import shop.mtcoding.securityapp.dto.UserResponse;
import shop.mtcoding.securityapp.model.User;
import shop.mtcoding.securityapp.model.UserRepository;
import shop.mtcoding.securityapp.service.UserService;

/**
 * 로그 레벨 : trace, debug, info, warn, error
 */


@Slf4j
@RequiredArgsConstructor
//@Controller
@RestController
public class HelloController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;

    @Value("${meta.name}")
    private String name;


    //필터에서 처리하는 것보다 스프링의 각종 기술의 도움을 받을 수 있다.
    //1. ExceptionHandler
    //2. 유효성 검사 - @Valid
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UserRequest.LoginDTO loginDTO){
        String jwt = userService.로그인(loginDTO);
        return ResponseEntity.ok().header(MyJwtProvider.HEADER, jwt).body("로그인완료");
    }

    @GetMapping("/users/1")
    public ResponseEntity<?> userCheck(
            @AuthenticationPrincipal MyUserDetails myUserDetails){

        Long id =myUserDetails.getUser().getId();
        String role = myUserDetails.getUser().getRole();
        return ResponseEntity.ok().body(id+" : "+role);
    }

    @GetMapping("/")
    public ResponseEntity<?> hello(){
        return ResponseEntity.ok().body(name);
    }

//    @GetMapping("/joinForm")
//    public String joinForm(){
//        return "joinForm";
//    }
//
//    @GetMapping("/loginForm")
//    public String loginForm(){
//        return "loginForm";
//    }



    //checkpoint : JSON으로 처리 필요
    @PostMapping("/join")
//    public ResponseEntity<?> join(UserRequest.JoinDTO joinDTO){
    public ResponseEntity<?> join(@RequestBody UserRequest.JoinDTO joinDTO){
        // select 됨
        UserResponse.JoinDto data = userService.회원가입(joinDTO);
        // select 안됨
        ResponseDTO<?> responseDTO = new ResponseDTO<>().data(data);
        return ResponseEntity.ok().body(responseDTO);
    }
}
