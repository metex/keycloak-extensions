package com.skoiy.keycloak;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.fasterxml.jackson.core.type.TypeReference;
import com.skoiy.keycloak.external.CredentialData;
import com.skoiy.keycloak.external.User;
import com.skoiy.keycloak.external.Verified;
import lombok.SneakyThrows;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.mockserver.integration.ClientAndServer;

import javax.ws.rs.WebApplicationException;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class PeanutsUserProviderTest {

	private static ClientAndServer mockServer;

//    @BeforeAll
//    public static void startMockServer() {
//        mockServer = startClientAndServer(8081);
//
//        Expectation[] expectations = new MockServerClient("localhost", 8081)
//                .when(
//                        request()
//                                .withMethod("GET")
//                                .withPath("/view/cart")
//                                .withCookies(
//                                        cookie("session", "4930456C-C718-476F-971F-CB8E047AB349")
//                                )
//                                .withQueryStringParameters(
//                                        param("cartId", "055CA455-1DF7-45BB-8535-4F83E7266092")
//                                )
//                )
//                .respond(
//                        response()
//                                .withBody("some_response_body")
//                );
//        System.out.println(Arrays.toString(expectations));
//
//        RequestDefinition[] requestDefinitions = new MockServerClient("localhost", 8081)
//                .retrieveRecordedRequests(
//                        request()
//                                .withPath("/view/cart")
//                                .withQueryStringParameter("cartId","055CA455-1DF7-45BB-8535-4F83E7266092")
//                                .withMethod("GET")
//                );
//        System.out.println(Arrays.toString(requestDefinitions));
//    }

//    @AfterAll
//    public static void stopMockServer() {
//        mockServer.stop();
//    }

//    @Test
//    public void simpleTest() {
//        CartManager cm = new CartManager();
//        cm.viewCart();
//
//        new MockServerClient("localhost", 8081)
//                .verify(
//                        request()
//                                .withPath("/view/cart"),
//                        VerificationTimes.atLeast(1)
//                );
//    }

    @Test
    public void testLoginAsUserWithInvalidPassword()
    {
        assertTrue(true);
    }

    @Test
    @SneakyThrows
    public void testGetUserById()
    {
        String baseUrl = "http://demo9781819.mockable.io";
        String id = "admin";
        String url = String.format("%s/%s", baseUrl, id);
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        SimpleHttp.Response response = SimpleHttp.doGet(url, httpClient).asResponse();
        if (response.getStatus() == 404) {
            throw new WebApplicationException(response.getStatus());
        }

        User u = response.asJson(User.class);
        System.out.println(u.getFirstName());
    }

    @Test
    @SneakyThrows
    public void testGeCredentialsData()
    {
        String baseUrl = "http://demo9781819.mockable.io";
        String id = "admin";
        String url = String.format("%s/%s/credentials", baseUrl, id);
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        SimpleHttp.Response response = SimpleHttp.doGet(url, httpClient).asResponse();
        if (response.getStatus() == 404) {
            throw new WebApplicationException(response.getStatus());
        }

        CredentialData u = response.asJson(CredentialData.class);
        System.out.println(u.getValue());
    }

    @Test
    @SneakyThrows
    public void testValidateCredentials()
    {
        String baseUrl = "http://demo9781819.mockable.io";
        String id = "admin";
        String password = "$2y$10$1/xlmIBAoz1SMgMTyAtr8eKhE33Truhg/t5xjic6VXclhgfEINv4i";
        String url = String.format("%s/validate", baseUrl);
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        SimpleHttp.Response response = SimpleHttp.doPost(url, httpClient)
                .param("username", id)
                .param("password", password)
                .asResponse();
        if (response.getStatus() == 404) {
            throw new WebApplicationException(response.getStatus());
        }

        Verified u = response.asJson(Verified.class);
        System.out.println(u.getVerified());
    }

    @Test
    @SneakyThrows
    public void testGetUsers() {
        String baseUrl = "http://demo9781819.mockable.io";
        int first = 1;
        int max = 2;
        String url = String.format("%s/users", baseUrl);
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        SimpleHttp.Response response = SimpleHttp.doGet(url, httpClient)
                .param("first", String.valueOf(first))
                .param("max", String.valueOf(max))
                .asResponse();
        if (response.getStatus() == 404) {
            throw new WebApplicationException(response.getStatus());
        }

        Object t = response.asJson(new TypeReference<>() {});
        System.out.println(t);
    }

    @Test
    @SneakyThrows
    public void testBCrypt()
    {
        String password = "1234567";
        String hash = "$2y$10$1/xlmIBAoz1SMgMTyAtr8eKhE33Truhg/t5xjic6VXclhgfEINv4i";
        BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(), hash);
        System.out.println(result.verified);
    }
}
