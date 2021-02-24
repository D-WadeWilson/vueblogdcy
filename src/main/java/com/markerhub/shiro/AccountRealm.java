package com.markerhub.shiro;

import cn.hutool.core.bean.BeanUtil;
import com.markerhub.entity.User;
import com.markerhub.service.UserService;
import com.markerhub.util.JwtUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class AccountRealm extends AuthorizingRealm {


    @Autowired
    JwtUtils jwtUtils;
    @Autowired
    UserService userService;

    //为了让realm支持jwt的凭证校验
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof JwtToken;
    }

    //用于认证 权限校验
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null;
    }

    //用于授权  登录认证校验  获取到token信息把里面的用户信息提取出来，跟数据库里的数据进行比较
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        JwtToken jwtToken = (JwtToken) token;

        String userId = jwtUtils.getClaimByToken((String) jwtToken.getPrincipal()).getSubject();

        User user = userService.getById(Long.valueOf(userId));
        if (user == null) {
            throw new UnknownAccountException("账户不存在");
        }

        if (user.getStatus() == -1) {
            throw new LockedAccountException("账户已被锁定");
        }

        AccountProfile profile = new AccountProfile();
        BeanUtil.copyProperties(user, profile);

        return new SimpleAuthenticationInfo(profile, jwtToken.getCredentials(), getName());
    }
}
