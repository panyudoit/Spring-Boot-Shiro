package org.inlighting.shiro;

import org.apache.shiro.authc.AuthenticationToken;

public class JWTToken implements AuthenticationToken {

    // 密钥
    private String token;

    public JWTToken(String token) {
        this.token = token;
    }

    ////身份
    @Override
    public Object getPrincipal() {
        return token;
    }

    //凭据
    @Override
    public Object getCredentials() {
        return token;
    }
}
