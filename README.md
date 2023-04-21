# CSR로 스프링 시큐리티 학습을 위한 리포지토리
## JWT를 이용한 stateless 서버 
- 토큰 확인해서 인증처리, 시간 지나면 토큰 반납 필요

1. UPAF -> 사용안함
   - POST, X-www-urlencoded 사용안함
   - 원래 순서 T -> F -> SF -> DS -> C
   - 바뀐 순서 T -> F -> SF -> UPAF 무력화 (loadByUser 호출 안 됨) -> DS -> C
   - /login 요청이 들어오면 Controller에서 인증 체크
2. 필터 중 JWT 검증 필터를 시큐리티 필터에 추가해 인가 체크
3. 인증 체크
   - /login 요청을 컨트롤러에서 처리
   - 필터에서 처리하기 위해서는 OM으로 직접 처리해야하므로 컨트롤러에서 처리
   - JWT 토큰을 이용한 로그인
     1. FilterSecurityInterceptor 작동
     2. JWT 토큰을 돌려준다.
     3. 강제 로그인 여부 판단
        1. 강제 로그인 
        2. 강제 로그인 X
     4. JWT Verifiyer Filter 추가해서 토큰 검증
        1. 강제로 로그인해서 세션에 추가한다. 
        2. FSI가 작동안하므로, SecurityContextHolder에 Authentication 객체를 추가
        3. 생성한 세션을 권한 체크에 사용한다.
4. 핸들러로 ResponseDTO로 응답
   1. authenticationEntryPoint()로 인증 실패 처리
   2. accessDeniedHandler()로 권한 실패 처리
5. authroizeRequests()로 인증, 권한, 인가 처리할 주소 설정
6. /login을 컨트롤러에서 처리
   1. ExceptionHandler 사용 가능
   2. 유효성 검사 어노테이션 사용가능
7. JwtVerifiyer에서 getenv
   - 윈도우에서는 HS512_SECRET로 환경변수에서 가져옴
   - 리눅스에서는 echo$HS512_SECRET로 환경변수에서 꺼내쓴다.
   - 사용하는 쉘과 쉘 프로파일이 일치하는지 여부를 확인해야한다.
   ```yaml
    #스프링의 프로퍼티
    meta:
      name: ${HS512.SECRET}
    #  name: $HS512.SECRET로도 가능 연산할때 {}사용
    #  OS 환경변수에 직접 접근 가능 파스칼 표기법에 ${}, 언더스코어를 사용
    #  스프링의 '.'을 '_'로 바꿔서 찾아준다. ('_'로 해도 똑같이 가능)
   ```
   ```java
    @Value("${meta.name}")
    private String secret;
   ```
   ```java
   System.getenv("HS512_SECRET");
   ```
8. BasicAuthenticationFilter 혹은 UsernamePasswordAuthenticationFilter를 상속한 JwtAuthorizationFilter 클래스 작성
   1. JWT 검증만 해도 되므로 SecurityFilter중 어떤 필터로든 가능
   2. BasicAuthenticationFilter에 등록하면 모든 주소에서 발동하는 필터가 된다.
   3. 시큐리티 설정의 FilterChain에 커스텀 필터로 적용
   ```java
   builder.addFilter(new JwtAuthorizationFilter(authenticationManager));
   ```
   ```java
   http.apply(new CustomSecurityFilterManager());
   ```
   4. UsernamePasswordAuthenticationToken로 Authentication 생성해, SecurityContextHolder에 추가
9. formLogin과 httpBasic을 사용안함 -> JwtAuthenticationFilter 필터
   - 생성자 주입에서는 AutehnticationManager를 의존성 주입 못함
   ```java
   @Bean
   //인증처리를 위해 빈으로 등록해 둬야한다.
   AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
   return authenticationConfiguration.getAuthenticationManager();
   }
   ```
   - UserDetailsService를 타지 않으면, username이 없다
   - 토큰 생성시에 유저 네임을 넣어서 전송하면 된다.
   - 페이로드 -> JWT가 확장성이 좋은 이유 -> 호환서버에도 사용가능하다.
   - 토큰이 없어도 필터를 탄다. -> 권한과 인증처리를 컨트롤러에게 맡긴다.
   - 있으면 세션 만들어서 저장, 없어도 헬스장에 진입하게 해줌
   - 시큐리티에게 위임할 수 있기 때문에
10. login 메서드는 컨트롤러에서 관리하는게 좋다.
   - 필터에서 처리하면 스프링의 각종 기술을 사용하기 어렵다.
   - 컨트롤러에서 처리하면 throw, valid 처리에 용이하다.
   ```java
       @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UserRequest.LoginDTO loginDTO){
        String jwt = userService.로그인(loginDTO);
        return ResponseEntity.ok().header(MyJwtProvider.HEADER, jwt).body("로그인완료");
    }
   ```
   ```java
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
   ```
11. 로그인(인증)이 필요한 페이지 요청시 반드시 JwtAuthenticationFilter를 탄다.
    - formLogin()을 해제했기 때문에, UsernamePasswordAuthenticationFilter가 비활성화
    - BasicAuthentication도 비활성화 상태
    - JwtAuthorizationFilter가 AuthenticationManager에 의존한다.
    - SecurityConfig에서 AuthenticationManager를 빈으로 등록해야 의존성 주입 가능
    - AuthenticationManager를 이용해 인증처리를 수행한다.
    1. UsernamePasswordAuthenticationFilter가 UsernamePasswordAuthenticationToken 토큰을 이용해 강제 로그인하도록 하는 방법
    ```java
        @Bean
    //인증처리를 위해 빈으로 등록해 둬야한다.
    AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
    ```
    ```java
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.authenticationManager=authenticationManager;
        this.userRepository=userRepository;

        //강제 인증처리
    //        UsernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(null, null, null);
    //        authenticationManager
    }
    ```
    ```java
        public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.authenticationManager=authenticationManager;
        this.userRepository=userRepository;

        //강제 인증 처리
        UsernamePasswordAuthenticationToken token= new UsernamePasswordAuthenticationToken(null, null, null);
        authenticationManager.authenticate(token);  //AuthenticationProvider -> UserDetailsService의 loadByUsername 강제 호출
        //loadByUsername는 SecurityContextHolder에 강제로 Authentication 객체를 주입한다.
    }
    ```
    2. SecurityContextHolder에 Authentication 객체를 강제로 주입하는 방법
    - 이 방법은 UserDetailsService를 타지 않는다.
    - JSESSIONID를 사용하지 않고 세션영역을 잠시 사용하는 방법
    ```java
                //UserDetailsService를 타지 않고 강제로 Authentication 객체를 만들어서 주입한다. -> 세션에 주입한다는 것
            //: 여기서 Username을 전달해야 유저네임을 찾을 수 있다.
            //페이로드 -> JWT가 확장성이 좋은 이유
            User user = User.builder().id(id).role(role).build();
            MyUserDetails myUserDetails = new MyUserDetails(user);
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(
                            myUserDetails,
                            myUserDetails.getPassword(),    //null
                            myUserDetails.getAuthorities()
                    );
            SecurityContextHolder.getContext().setAuthentication(authentication);
    ```
    3. 에러가 발생하는 이유
       - Jwt토큰 생성시 name이 없기 때문에
       - Jwt토큰 생성시에 username을 추가해주면 된다.
       - stateless의 장점을 유지하도록 하기 위해 DB에 조회는 피한다. -> 확장성이 용이하다.
       - 서버에서는 토큰 서명과 조회만 하기 때문에 가볍다.
    ```java
        @GetMapping("/users/{id}")
    public ResponseEntity<?> userCheck(
            @PathVariable Long id,
            @AuthenticationPrincipal MyUserDetails myUserDetails){
        //@AuthenticationPrincipal Authentication에 접근해서 UserDetails 타입을 가져옴
        //: loginArgumentResolver 대신 해줌

        if(id.longValue()==myUserDetails.getUser().getId()){
            String username =myUserDetails.getUser().getUsername();
            String role = myUserDetails.getUser().getRole();
            return new ResponseEntity<>(username+" : "+role, HttpStatus.OK);
        }
        else if(myUserDetails.getUser().getRole().equals("ADMIN")){
            //admin 서버를 따로 만드는 게 낫다.
            String username =myUserDetails.getUser().getUsername();
            String role = myUserDetails.getUser().getRole();
            return new ResponseEntity<>(username+" : "+role, HttpStatus.OK);
        }
        else{
            return new ResponseEntity<>("권한 없음", HttpStatus.FORBIDDEN);
        }

        //        return ResponseEntity.ok().body(username+" : "+role);
       }
    ```
    ```java
        public static String create(User user) {
        String jwt = JWT.create()
                .withSubject(SUBJECT)
                .withExpiresAt(new Date(System.currentTimeMillis() + EXP))
                .withClaim("id", user.getId())
                //유저 네임이 없는데 -> 강제로 로그인할 때 (UserDetailsService를 타지 않아) 유저 이름을 못찾으므로 여기서 넣어줘야 찾을 수 있다.
                .withClaim("username", user.getUsername())
                .withClaim("role", user.getRole())
                .sign(Algorithm.HMAC512(SECRET));
        return TOKEN_PREFIX + jwt;
    }
    ```
    ```java
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
    ```
    
12. 토큰이 없어도 다음 필터로 이동한다.
    - 토큰이 있는지만 검사하는 JwtAuthorizationFilter
    - 토큰이 있으면 세션 생성해 메모리에 로그인한 유저 정보를 저장
    - 토큰이 없으면 다음 필터로 이동한다.
    - 요청이 넘어가면 시큐리티에게 권한과 인증처리를 위임할 수 있기 때문에

13. 토큰 유효성 여부만 검사하는 JWT 기반 인증 서버
    - JwtAuthenticationFilter로 토큰 검증 완료시, 세션 영역에 로그인 유저 정보를 보관한다.
    - 토큰 검증한 후, FilterSecurityInterceptor가 세션 영역에 데이터가 있으면 통과시키고, 없으면 요청을 거부한다.
