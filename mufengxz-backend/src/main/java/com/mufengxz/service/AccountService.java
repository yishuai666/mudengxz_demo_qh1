package com.mufengxz.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.mufengxz.entity.dto.Account;
import com.mufengxz.entity.vo.request.EmailRegisterVo;
import com.mufengxz.entity.vo.response.ConfirmResetVo;
import com.mufengxz.entity.vo.response.EmailResetVo;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

public interface AccountService extends IService<Account>, UserDetailsService {
    //根据用户名或邮箱查询用户
    Account findAccountByNameOrEmail(String text);
    //邮箱验证码
    String registerEmailVerifyCode(String type, String email, String ip);
    //邮箱账户注册
    String registerEmailAccount(EmailRegisterVo vo);
    //重置密码，获取验证码
    String resetConfirm(ConfirmResetVo vo);
    //保存新密码
    String resetEmailAccountPassword(EmailResetVo vo);
}
