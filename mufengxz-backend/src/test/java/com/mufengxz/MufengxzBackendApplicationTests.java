package com.mufengxz;

import com.mufengxz.entity.dto.Account;
import com.mufengxz.service.AccountService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@SpringBootTest
class MufengxzBackendApplicationTests {

    AccountService accountService;
    @Test
    void contextLoads() {
        System.out.println(new BCryptPasswordEncoder().encode("123456"));
        Account account = accountService.findAccountByNameOrEmail("test");
        System.out.println(account.getPassword());
    }

}
