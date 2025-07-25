package com.data.session13.model.dto.request;

import lombok.Data;

@Data
public class AuthRequest {
    private String username;
    private String password;
}