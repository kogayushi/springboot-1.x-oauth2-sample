package com.example.oauth.interfaces.rest;

import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;

@RequiredArgsConstructor
@RestController
public class SampleController {

    private final OAuth2RestTemplate oAuth2RestTemplate;

    @GetMapping("/user")
    public Principal user(Principal principal) {
        return principal;
    }

    @GetMapping(value = "/contacts", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ContactGroups contacts() throws URISyntaxException {
        ContactGroups contacts = oAuth2RestTemplate.getForObject(new URI("https://people.googleapis.com/v1/contactGroups"), ContactGroups.class);
        return contacts;

    }
}
