package shop.mtcoding.securityapp.dto;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class ResponseDTO<T> {
    private Integer status;
    private String msg; // 제목
    private T data; // 상세내용

    public ResponseDTO() {
        this.status = 200;
        this.msg = "성공";
    }

    public ResponseDTO<?> data(T data){
        this.data = data;
        return this;
    }

    public ResponseDTO<?> fail(Integer status, String msg, T data){
        this.status = status;
        this.msg = msg;
        this.data = data;
        return this;
    }
}
