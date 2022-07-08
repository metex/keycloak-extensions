package com.skoiy.keycloak;

import com.skoiy.keycloak.external.User;

import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

class UserCache {
	private static final Map<String, User> cache = new HashMap<>();

	static int getCount() {
		return cache.size();
	}

	static void addUser(User user) {
		cache.put(user.getUsername(), user);
	}

	static List<User> getUsers() {
		return cache.entrySet().stream()
			.map(Map.Entry::getValue)
			.sorted(Comparator.comparing(User::getUsername))
			.collect(Collectors.toList());
	}

	static List<User> findUsers(String search) {
		return cache.entrySet().stream()
			.map(Map.Entry::getValue)
			.filter(u -> (u.getUsername() + ";" + u.getFirstname() + ";" + u.getLastname()).contains(search))
			.sorted(Comparator.comparing(User::getUsername))
			.collect(Collectors.toList());
	}

}
