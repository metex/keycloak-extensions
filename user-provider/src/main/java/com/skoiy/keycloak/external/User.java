package com.skoiy.keycloak.external;

import lombok.Data;

@Data
public class User {
	private Integer id_user;
	private String user_token;
	private String username;
	private String firstname;
	private String lastname;
	private String email;
	private String password;
	private Boolean verified;
	private Boolean active;
	private String lang;
	private String updated_at;
	private String created_at;
	private String register_Date;
	private String remember_token;
	private String birthday; // some custom attributes that could be loaded from database
	private String gender;  // some custom attributes that could be loaded from database
//	private List<String> groups;
//	private List<String> roles;

	public String getUsername() {
		return this.username;
	}

}
