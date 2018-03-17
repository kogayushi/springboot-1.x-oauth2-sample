package com.example.oauth.infrastructure.configuration;

import lombok.RequiredArgsConstructor;
import org.springframework.security.web.DefaultRedirectStrategy;

import javax.servlet.http.HttpSession;

@RequiredArgsConstructor
public class MyRedirectStrategy extends DefaultRedirectStrategy {

    private final HttpSession session;

    @Override
    protected String calculateRedirectUrl(String contextPath, String url) {
        // FIXME サンプルコードは決め打ちだが、プロダクションで利用する場合はリダイレクト先URLのスキーマが特定文字列のときだけsessionidを付与するなどしてコントロールすること
        return super.calculateRedirectUrl(contextPath, url) + "?jsessionid=" + session.getId();

    }
}
