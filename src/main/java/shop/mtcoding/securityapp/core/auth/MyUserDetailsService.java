package shop.mtcoding.securityapp.core.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import shop.mtcoding.securityapp.model.User;
import shop.mtcoding.securityapp.model.UserRepository;

import java.util.Optional;

@RequiredArgsConstructor
@Service
public class MyUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    // /login + POST + FormUrlEncoded + username, password
    // Authentication 객체 만들어짐
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("UserDetailsService loadUserByUsername 실행됨");
        Optional<User> userOP = userRepository.findByUsername(username);
        if(userOP.isPresent()){
            return new MyUserDetails(userOP.get());
        }else{
            return null;
        }
    }
}
