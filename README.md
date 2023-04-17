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
   ```yaml
    #스프링의 프로퍼티
    meta:
      name: ${HS512.SECRET}
    #  name: $HS512.SECRET로도 가능 연산할때 {}사용
    #  OS 환경변수에 직접 접근 가능 파스칼 표기법에 ${}, 언더스코어를 사용
    #  스프링의 '.'을 '_'로 바꿔서 찾아준다. ('_'로 해도 똑같이 가능)
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
   4. UPAT로 Authentication 생성해, SecurityContextHolder에 추가