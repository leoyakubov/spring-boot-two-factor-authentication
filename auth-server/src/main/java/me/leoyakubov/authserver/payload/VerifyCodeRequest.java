package me.leoyakubov.authserver.payload;

import lombok.Data;

@Data
public class VerifyCodeRequest {
    private String username;
    private String code;
}
