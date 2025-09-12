#include <iostream>
#include <string>
#include <memory>
#include <cstdio>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

// Deleters for OpenSSL types
struct BIO_deleter { void operator()(BIO* p) const { BIO_free_all(p); } };
struct EVP_PKEY_deleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct EVP_PKEY_CTX_deleter { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
struct X509_deleter { void operator()(X509* p) const { X509_free(p); } };
struct X509_NAME_deleter { void operator()(X509_NAME* p) const { X509_NAME_free(p); } };

void handle_openssl_errors() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

void gen_ec_key() {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_deleter> ctx(EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL));
    if (!ctx) handle_openssl_errors();

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) handle_openssl_errors();

    char group_name[] = "prime256v1";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0),
        OSSL_PARAM_construct_end()
    };

    if (EVP_PKEY_CTX_set_params(ctx.get(), params) <= 0) handle_openssl_errors();

    EVP_PKEY *pkey_ptr = NULL;
    if (EVP_PKEY_generate(ctx.get(), &pkey_ptr) <= 0) handle_openssl_errors();
    std::unique_ptr<EVP_PKEY, EVP_PKEY_deleter> pkey(pkey_ptr);

    std::unique_ptr<BIO, BIO_deleter> bio_out(BIO_new_fp(stdout, BIO_NOCLOSE));
    if (PEM_write_bio_PrivateKey_traditional(bio_out.get(), pkey.get(), NULL, NULL, 0, NULL, NULL) != 1) {
        handle_openssl_errors();
    }
}

void gen_rsa_key() {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_deleter> ctx(EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL));
    if (!ctx) handle_openssl_errors();

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) handle_openssl_errors();

    size_t bits = 2048;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_RSA_BITS, &bits),
        OSSL_PARAM_construct_end()
    };

    if (EVP_PKEY_CTX_set_params(ctx.get(), params) <= 0) handle_openssl_errors();

    EVP_PKEY *pkey_ptr = NULL;
    if (EVP_PKEY_generate(ctx.get(), &pkey_ptr) <= 0) handle_openssl_errors();
    std::unique_ptr<EVP_PKEY, EVP_PKEY_deleter> pkey(pkey_ptr);

    std::unique_ptr<BIO, BIO_deleter> bio_out(BIO_new_fp(stdout, BIO_NOCLOSE));
    if (PEM_write_bio_PrivateKey_traditional(bio_out.get(), pkey.get(), NULL, NULL, 0, NULL, NULL) != 1) {
        handle_openssl_errors();
    }
}

void gen_cert(const char* key_path) {
    FILE* fp = fopen(key_path, "r");
    if (!fp) {
        perror(key_path);
        exit(1);
    }

    std::unique_ptr<EVP_PKEY, EVP_PKEY_deleter> pkey(PEM_read_PrivateKey(fp, NULL, NULL, NULL));
    fclose(fp);

    if (!pkey) {
        fprintf(stderr, "Error reading private key from %s\n", key_path);
        handle_openssl_errors();
    }

    std::unique_ptr<X509, X509_deleter> x509(X509_new());
    if (!x509) {
        handle_openssl_errors();
    }

    ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 1);

    X509_gmtime_adj(X509_getm_notBefore(x509.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509.get()), 3650L * 24 * 60 * 60);

    if (X509_set_pubkey(x509.get(), pkey.get()) != 1) {
        handle_openssl_errors();
    }

    std::unique_ptr<X509_NAME, X509_NAME_deleter> name(X509_NAME_new());
    if (!name) {
        handle_openssl_errors();
    }
    
    X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC, (const unsigned char*)"Generated", -1, -1, 0);
    
    if (X509_set_subject_name(x509.get(), name.get()) != 1) {
        handle_openssl_errors();
    }
    if (X509_set_issuer_name(x509.get(), name.get()) != 1) { // self-signed
        handle_openssl_errors();
    }

    if (X509_sign(x509.get(), pkey.get(), EVP_sha256()) == 0) {
        handle_openssl_errors();
    }

    std::unique_ptr<BIO, BIO_deleter> bio_out(BIO_new_fp(stdout, BIO_NOCLOSE));
    if (PEM_write_bio_X509(bio_out.get(), x509.get()) != 1) {
        handle_openssl_errors();
    }
}

void print_usage(const char* prog_name) {
    std::cerr << "Usage: " << prog_name << " <command>\n"
              << "Commands:\n"
              << "  gen_ec_key         Generate EC key (prime256v1)\n"
              << "  gen_rsa_key        Generate RSA key (2048-bit, PKCS#1)\n"
              << "  gen_cert <keyfile> Generate self-signed certificate from a key file\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string command = argv[1];

    if (command == "gen_ec_key") {
        if (argc != 2) {
            print_usage(argv[0]);
            return 1;
        }
        gen_ec_key();
    } else if (command == "gen_rsa_key") {
        if (argc != 2) {
            print_usage(argv[0]);
            return 1;
        }
        gen_rsa_key();
    } else if (command == "gen_cert") {
        if (argc != 3) {
            print_usage(argv[0]);
            return 1;
        }
        gen_cert(argv[2]);
    } else {
        std::cerr << "Unknown command: " << command << "\n";
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}