package com.skoiy.keycloak.external;

import com.fasterxml.jackson.core.type.TypeReference;
import com.skoiy.keycloak.Constants;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;

import javax.ws.rs.WebApplicationException;
import java.util.List;

/**
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 */
@Slf4j
public class UsersClientSimpleHttp implements UsersClient {

    private final CloseableHttpClient httpClient;
    private final String baseUrl;

    public UsersClientSimpleHttp(KeycloakSession session, ComponentModel model) {
        this.httpClient = session.getProvider(HttpClientProvider.class).getHttpClient();
        this.baseUrl = model.get(Constants.BASE_URL);
    }

    @Override
    @SneakyThrows
    public List<User> getUsers(String search, int first, int max) {
        String url = String.format("%s/users", baseUrl);
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        SimpleHttp.Response response = SimpleHttp.doGet(url, httpClient)
                .param("first", String.valueOf(first))
                .param("max", String.valueOf(max))
                .asResponse();
        if (response.getStatus() == 404) {
            throw new WebApplicationException(response.getStatus());
        }

        log.info("getUsers {}", response.getStatus());
        return response.asJson(new TypeReference<>() {});
    }

    @Override
    public List<User> login(String username, String password) {
        return null;
    }

    @Override
    @SneakyThrows
    public User getUserById(String id) {
        String url = String.format("%s/%s?filter=email", baseUrl, id);
        SimpleHttp.Response response = SimpleHttp.doGet(url, httpClient).asResponse();
        if (response.getStatus() == 404) {
            throw new WebApplicationException(response.getStatus());
        }
        log.info("status {}", response.getStatus());
        return response.asJson(User.class);
    }

    @Override
    @SneakyThrows
    public CredentialData getCredentialData(String id) {
        String url = String.format("%s/%s/credentials", baseUrl, id);
        SimpleHttp.Response response = SimpleHttp.doGet(url, httpClient).asResponse();
        if (response.getStatus() == 404) {
            throw new WebApplicationException(response.getStatus());
        }
        return response.asJson(CredentialData.class);
    }

    @Override
    @SneakyThrows
    public Verified validateCredentials(String id, String password) {
        String url = String.format("%s/validate", baseUrl);
        SimpleHttp.Response response = SimpleHttp.doPost(url, httpClient)
                .param("username", id)
                .param("password", password)
                .asResponse();
        if (response.getStatus() == 404) {
            throw new WebApplicationException(response.getStatus());
        }
        return response.asJson(Verified.class);
    }

}
