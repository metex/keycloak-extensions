package com.skoiy.keycloak.external;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class Verified {
	private Boolean verified;
	private String reason;
	private User data;
}
