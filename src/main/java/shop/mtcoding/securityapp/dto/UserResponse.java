package shop.mtcoding.securityapp.dto;

import lombok.Getter;
import lombok.Setter;
import shop.mtcoding.securityapp.core.util.MyDateUtils;
import shop.mtcoding.securityapp.model.User;

public class UserResponse {

    @Getter @Setter
    public static class JoinDto {
        private Long id;
        private String username;
        private String email;
        private String role;
        private String createdAt;

        public JoinDto(User user) {
            this.id = user.getId();
            this.username = user.getUsername();
            this.email = user.getEmail();
            this.role = user.getRole();
            this.createdAt = MyDateUtils.toStringFormat(user.getCreatedAt());
        }
    }
}
