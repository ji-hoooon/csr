package shop.mtcoding.securityapp.model;

import java.time.LocalDateTime;

import javax.persistence.Entity;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor // hibernate가 ORM시에 new하려고 필요
@Getter
@Table(name = "user_tb")
@Entity // Hibernate가 관리 (영속, 비영속, 준영속)
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private Integer passwordWrongCount;
    private String username;
    private String password;
    private String email;
    private String role; // USER, MANAGER, ADMIN
    private Boolean status; // true, false

    private LocalDateTime createdAt; // LocalDateTime -> Timestamp
    private LocalDateTime updateAt;

    @PrePersist // insert 시에 동작
    public void onCreate() {
        this.createdAt = LocalDateTime.now();
    }

    @PreUpdate // update 시에 동작
    public void onUpdate() {
        this.updateAt = LocalDateTime.now();
    }

    @Builder
    public User(Long id, String username, String password, String email, String role, Boolean status,
            LocalDateTime createdAt, LocalDateTime updateAt) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.email = email;
        this.role = role;
        this.status = status;
        this.createdAt = createdAt;
        this.updateAt = updateAt;
    }
}
