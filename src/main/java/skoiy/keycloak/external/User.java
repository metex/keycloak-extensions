package skoiy.keycloak.external;

import lombok.Data;

import java.util.List;

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
