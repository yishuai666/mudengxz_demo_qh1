package com.mufengxz.service.impl;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.conditions.update.UpdateChainWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.mufengxz.entity.dto.Account;
import com.mufengxz.entity.vo.request.EmailRegisterVo;
import com.mufengxz.entity.vo.response.ConfirmResetVo;
import com.mufengxz.entity.vo.response.EmailResetVo;
import com.mufengxz.mapper.AccountMapper;
import com.mufengxz.service.AccountService;
import com.mufengxz.utils.Const;
import com.mufengxz.utils.FlowUtils;
import jakarta.annotation.Resource;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;


@Service
public class AccountServiceImpl extends ServiceImpl<AccountMapper, Account> implements AccountService {

    @Resource
    AmqpTemplate amqpTemplate;
    @Resource
    StringRedisTemplate stringRedisTemplate;
    @Resource
    FlowUtils flowUtils;
    @Resource
    PasswordEncoder encoder;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = this.findAccountByNameOrEmail(username);
        if(account == null) {
            throw new UsernameNotFoundException("用户名或密码错误");
        }
        return User
                .withUsername(username)
                .password(account.getPassword())
                .roles(account.getRole())
                .build();
    }

    public Account findAccountByNameOrEmail(String text) {
        return this.query()
                .eq("username", text).or()
                .eq("email", text)
                .one();
    }

    //验证码
    @Override
    public String registerEmailVerifyCode(String type, String email, String ip) {
        //防止同一时间同一ip多次调用
        synchronized (ip.intern()) {
            if(!this.verifyLimit(ip))
                return "请求频繁，请稍后再试！";

        Random random = new Random();
        int code = random.nextInt(899999) + 100000;
        Map<String, Object> data = Map.of("type", type, "email", email, "code", code);
        amqpTemplate.convertAndSend("mail", data);
        stringRedisTemplate.opsForValue()
                .set(Const.VERIFY_EMAIL_DATA + email,String.valueOf(code), 5, TimeUnit.MINUTES);
        return null;
        }
    }
    //新注册用户
    @Override
    public String registerEmailAccount(EmailRegisterVo vo) {
        String email = vo.getEmail();
        String username = vo.getUsername();
        String key = Const.VERIFY_EMAIL_DATA + email;
        String code = stringRedisTemplate.opsForValue().get(key);
        if (code == null) return "请先获取验证码！";
        if(!code.equals(vo.getCode())) return "验证码输入错误，请重新输入";
        if(this.existsAccountByEmail(email)) return "此电子邮箱已被其他用户注册！";
        if(this.existsAccountByUsername(username)) return "此用户名已被其他人注册，请使用新的用户名！";
        String password = encoder.encode(vo.getPassword());
        Account account = new Account(null, username, password, email, "user", new Date());
        if(this.save(account)) {
            stringRedisTemplate.delete(key);
            return null;
        } else {
            return "内部错误，请联系管理员！";
        }
    }

    @Override
    public String resetConfirm(ConfirmResetVo vo) {
        String email = vo.getEmail();
        String code = stringRedisTemplate.opsForValue().get(Const.VERIFY_EMAIL_DATA + email);
        if(code == null) return "请先获取验证码！";
        if(!code.equals(vo.getCode())) return "验证码错误，请重新输入！";
        return null;
    }

    @Override
    public String resetEmailAccountPassword(EmailResetVo vo) {
        String email = vo.getEmail();
        String verify = stringRedisTemplate.opsForValue().get(Const.VERIFY_EMAIL_DATA + email);
        if(verify != null) return verify;
        String password = encoder.encode(vo.getPassword());
        boolean update = this.update().eq("email", email).set("password", password).update();
        if (update) {
            stringRedisTemplate.delete(Const.VERIFY_EMAIL_DATA + email);
        }
        return null;
    }

    //验证邮箱是否已存在
    private boolean existsAccountByEmail(String email) {
        return this.baseMapper.exists(Wrappers.<Account>query().eq("email", email));
    }

    //验证用户名是否已存在
    private boolean existsAccountByUsername(String username) {
        return this.baseMapper.exists(Wrappers.<Account>query().eq("username", username));
    }
    //ip限流
    private boolean verifyLimit(String ip) {
        String key = Const.VERIFY_EMAIL_LIMIT + ip;
        return flowUtils.limitOnceCheck(ip, 60);
    }

    //重置密码，获取验证码
}
