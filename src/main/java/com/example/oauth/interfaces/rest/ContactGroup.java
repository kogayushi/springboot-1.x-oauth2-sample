package com.example.oauth.interfaces.rest;

import lombok.Data;

import java.util.Map;

@Data
public class ContactGroup {
    private String resourceName;
    private String etag;
    private Map<String ,String> metadata;
    private String groupType;
    private String name;
    private String formattedName;
    private Integer memberCount;
}
