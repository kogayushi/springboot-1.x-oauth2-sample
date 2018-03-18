package com.example.oauth.infrastructure.configuration;

import lombok.RequiredArgsConstructor;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

@RequiredArgsConstructor
public class MyRedirectStrategy extends DefaultRedirectStrategy {

    private final HttpSession session;
    private final HttpServletRequest request;
    private final CookieCsrfTokenRepository csrfTokenRepository = new CookieCsrfTokenRepository();

    @Override
    protected String calculateRedirectUrl(String contextPath, String url) {
        /*
         * サンプルコードは決め打ちだが、プロダクションで利用する場合はスマホ用のログインURLにアクセスされたときだけ、
         * そのアプリ用のカスタムスキーマを指定してsessionidをフラグメント部にセットするなどしてコントロールすること
         */

        String token = csrfTokenRepository.loadToken(request).getToken();
        return "my-test-app://path/to/top/for/example#jsessionid=" + session.getId() + "&X-CSRF-TOKEN=" + token;
    }
}
