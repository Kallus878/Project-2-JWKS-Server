#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include <cpprest/http_client.h>
#include <cpprest/json.h>

using namespace web; // Common features for REST
using namespace web::http; // Common features for HTTP
using namespace web::http::client; // HTTP client features

TEST_CASE("JWKS Server Tests", "[jwks]") {
    http_client client(U("http://localhost:8080/.well-known/jwks.json"));

    SECTION("Should respond with status 200") {
        http_request request(methods::GET);
        client.request(request).then([](http_response response) {
            REQUIRE(response.status_code() == status_codes::OK);
        }).wait();
    }

    SECTION("Should return valid JWKS format") {
        http_request request(methods::GET);
        client.request(request).then([](http_response response) {
            REQUIRE(response.status_code() == status_codes::OK);
            auto jsonResponse = response.extract_json().get();
            REQUIRE(jsonResponse.has_field(U("keys")));
            REQUIRE(jsonResponse[U("keys")].is_array());
        }).wait();
    }

    SECTION("Keys should have expected properties") {
        http_request request(methods::GET);
        client.request(request).then([](http_response response) {
            REQUIRE(response.status_code() == status_codes::OK);
            auto jsonResponse = response.extract_json().get();
            auto keys = jsonResponse[U("keys")].as_array();

            for (const auto& key : keys) {
                REQUIRE(key.has_field(U("kty"))); // Key Type
                REQUIRE(key.has_field(U("kid"))); // Key ID
                REQUIRE(key.has_field(U("alg"))); // Algorithm
                REQUIRE(key.has_field(U("use"))); // Public Key Use
                REQUIRE(key.has_field(U("n")));   // Modulus
                REQUIRE(key.has_field(U("e")));   // Exponent
            }
        }).wait();
    }

    SECTION("Should return key when requested by kid") {
        http_request request(methods::GET);
        client.request(request).then([](http_response response) {
            auto jsonResponse = response.extract_json().get();
            auto keys = jsonResponse[U("keys")].as_array();
            auto kid = keys[0][U("kid")].as_string(); // Get first key's kid

            http_client keyClient(U("http://localhost:8080/.well-known/jwks.json?kid=") + kid);
            keyClient.request(methods::GET).then([kid](http_response keyResponse) {
                REQUIRE(keyResponse.status_code() == status_codes::OK);
                auto keyJsonResponse = keyResponse.extract_json().get();
                REQUIRE(keyJsonResponse[U("keys")].as_array().size() == 1);
                REQUIRE(keyJsonResponse[U("keys")][0][U("kid")].as_string() == kid);
            }).wait();
        }).wait();
    }
}
