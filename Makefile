build:
	mvn clean package install

build-userprovider:
	mvn clean install -pl user-provider -am
	cp user-provider/target/com.skoiy.keycloak-user-provider.jar ~/lab/environe/conf/keycloak/providers
	docker exec -it keycloak /opt/keycloak/bin/kc.sh build
	docker restart keycloak

build-rest-endpoint:
	mvn clean install -pl rest-endpoint -am
	cp rest-endpoint/target/com.skoiy.keycloak-rest-endpoint.jar ~/lab/environe/conf/keycloak/providers
	docker exec -it keycloak /opt/keycloak/bin/kc.sh build
	docker restart keycloak

build-tokenmapper:
	mvn clean install -pl tokenmapper -am

build-required-action:
	mvn clean install -pl required-action -am
