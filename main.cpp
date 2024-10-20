#include <iostream>
#include <string>
#include <jwt-cpp/jwt.h>
#include <httplib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sqlite3.h>

// Converts BIGNUM into a raw string representation
std::string bignum_to_raw_string(const BIGNUM *bn) {
    int bn_size = BN_num_bytes(bn);
    std::string raw(bn_size, 0);
    BN_bn2bin(bn, reinterpret_cast<unsigned char *>(&raw[0]));
    return raw;
}

// Extracts public key from EVP_PKEY and returns in PEM format
std::string extract_pub_key(EVP_PKEY *pkey) {
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);
    char *data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

// Extracts private key from EVP_PKEY and returns in PEM format
std::string extract_priv_key(EVP_PKEY *pkey) {
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    char *data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

// Encodes string into Base64
std::string base64_url_encode(const std::string &data) {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string ret;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    for (size_t n = 0; n < data.size(); n++) {
        char_array_3[i++] = data[n];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++) {
                ret += base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 3; j++) {
            char_array_3[j] = '\0';
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (int j = 0; j < i + 1; j++) {
            ret += base64_chars[char_array_4[j]];
        }    
    }

    // Replace '+' with '-', '/' with '_' and remove '='
    std::replace(ret.begin(), ret.end(), '+', '-');
    std::replace(ret.begin(), ret.end(), '/', '_');
    ret.erase(std::remove(ret.begin(), ret.end(), '='), ret.end());

    return ret;
}

// Database filename
const char* db_filename = "totally_not_my_privateKeys.db";

// Function to serialize private key to PEM format
std::string serialize_private_key(EVP_PKEY *pkey) {
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

// Function to deserialize private key from PEM format
EVP_PKEY* deserialize_private_key(const std::string &pem) {
    BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pkey;
}

// Function to initialize database
void init_db(sqlite3* &db) {
    int rc = sqlite3_open(db_filename, &db);
    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    const char *create_table_sql = R"(
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    )";
    char *err_msg = nullptr;
    rc = sqlite3_exec(db, create_table_sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << err_msg << std::endl;
        sqlite3_free(err_msg);
    }
}

// Function to save a private key to the database
void save_key(sqlite3* db, EVP_PKEY *pkey, int exp) {
    std::string key = serialize_private_key(pkey);
    sqlite3_stmt *stmt;
    const char *insert_sql = "INSERT INTO keys (key, exp) VALUES (?, ?)";
    sqlite3_prepare_v2(db, insert_sql, -1, &stmt, NULL);
    sqlite3_bind_blob(stmt, 1, key.data(), key.size(), SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, exp);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// Function to retrieve a key from the database
EVP_PKEY* get_key(sqlite3* db, bool expired) {
    sqlite3_stmt *stmt;
    const char *query_sql = expired ? "SELECT key FROM keys WHERE exp < strftime('%s', 'now') LIMIT 1"
                                    : "SELECT key FROM keys WHERE exp >= strftime('%s', 'now') LIMIT 1";
    sqlite3_prepare_v2(db, query_sql, -1, &stmt, NULL);
    EVP_PKEY* pkey = nullptr;

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const void *key_blob = sqlite3_column_blob(stmt, 0);
        int key_size = sqlite3_column_bytes(stmt, 0);
        std::string key(reinterpret_cast<const char*>(key_blob), key_size);
        pkey = deserialize_private_key(key);
    }

    sqlite3_finalize(stmt);
    return pkey;
}

// Main function
int main() {
    // Initialize SQLite database
    sqlite3 *db = nullptr;
    init_db(db);

    // Generate RSA key pair
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    // Save two keys: one expired and one valid
    save_key(db, pkey, static_cast<int>(std::time(nullptr) - 1)); // Expired key
    EVP_PKEY_free(pkey);

    // Generate a valid key
    pkey = EVP_PKEY_new();
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    save_key(db, pkey, static_cast<int>(std::time(nullptr) + 3600)); // valid key
    EVP_PKEY_free(pkey);

    // Start HTTP server
    httplib::Server svr;

    // Creates an unexpired and signed JWT on POST request
    svr.Post("/auth", [&](const httplib::Request &req, httplib::Response &res) {
        // If request is not POST --> return
        if (req.method != "POST") {
            res.status = 405;  // Method Not Allowed
            res.set_content("Method Not Allowed", "text/plain");
            return;
        }

        // Check if the "expired" query parameter is set to "true"
        bool expired = req.has_param("expired") && req.get_param_value("expired") == "true";
        EVP_PKEY *key = get_key(db, expired);
        if (!key) {
            res.status = 404; // Not Found
            res.set_content("No valid key found", "text/plain");
            return;
        }

        // Create JWT token
        auto now = std::chrono::system_clock::now();
        auto token = jwt::create()
            .set_issuer("auth0")
            .set_type("JWT")
            .set_payload_claim("sample", jwt::claim(std::string("test")))
            .set_issued_at(now)
            .set_expires_at(expired ? now - std::chrono::seconds{1} : now + std::chrono::hours{24})
            .set_key_id(expired ? "expiredKID" : "goodKID")
            .sign(jwt::algorithm::rs256(extract_pub_key(key), serialize_private_key(key)));

        res.set_content(token, "text/plain");
        EVP_PKEY_free(key);
    });

    // Serves the public keys in JWKS format
    svr.Get("/.well-known/jwks.json", [&](const httplib::Request &, httplib::Response &res) {
        // Retrieve valid keys and create JWKS
        sqlite3_stmt *stmt;
        const char *query_sql = "SELECT key FROM keys WHERE exp >= strftime('%s', 'now')";
        sqlite3_prepare_v2(db, query_sql, -1, &stmt, NULL);
        
        std::string jwks = R"({"keys":[)";
        bool first = true;

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void *key_blob = sqlite3_column_blob(stmt, 0);
            int key_size = sqlite3_column_bytes(stmt, 0);
            std::string key(reinterpret_cast<const char*>(key_blob), key_size);
            EVP_PKEY* pkey = deserialize_private_key(key);
            
            if (!first) {
                jwks += ",";
            }
            first = false;

            BIGNUM* n = NULL;
            BIGNUM* e = NULL;

            // Check if RSA public key parameter retrieval fails
            if (EVP_PKEY_get_bn_param(pkey, "n", &n) && EVP_PKEY_get_bn_param(pkey, "e", &e)) {
                std::string n_encoded = base64_url_encode(bignum_to_raw_string(n));
                std::string e_encoded = base64_url_encode(bignum_to_raw_string(e));

                // Initialize JWKS string
                jwks += R"({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": ")" + n_encoded + R"(",
                    "e": ")" + e_encoded + R"("
                })";
            }
            BN_free(n);
            BN_free(e);
            EVP_PKEY_free(pkey);
        }
        jwks += "]}";
        sqlite3_finalize(stmt);
        res.set_content(jwks, "application/json");
    });

    // Catch-all handlers for other methods
    auto methodNotAllowedHandler = [](const httplib::Request &req, httplib::Response &res) {
        if (req.path == "/auth" || req.path == "/.well-known/jwks.json") {
            res.status = 405;
            res.set_content("Method Not Allowed", "text/plain");
        } else {
            res.status = 404;
            res.set_content("Not Found", "text/plain");
        }
    };

    // Handles unsupported method requests
    svr.Get(".*", methodNotAllowedHandler);
    svr.Post(".*", methodNotAllowedHandler);
    svr.Put(".*", methodNotAllowedHandler);
    svr.Delete(".*", methodNotAllowedHandler);
    svr.Patch(".*", methodNotAllowedHandler);

    svr.listen("127.0.0.1", 8080);

    // Cleanup
    sqlite3_close(db);
    return 0;
}
