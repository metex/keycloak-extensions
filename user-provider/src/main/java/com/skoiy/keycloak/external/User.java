package com.skoiy.keycloak.external;

import lombok.Data;

@Data
public class User {
	private String username;
	private String firstName;
	private String lastName;
	private String email;
	private String birthday;
	private String gender;
//	private List<String> groups;
//	private List<String> roles;
}
