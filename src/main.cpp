#include <iostream>
#include <vector>
#include <fstream>
#include <chrono>
#include <exception>
#include <filesystem>
#include <algorithm>
#include <map>

#include <string.h>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>


#define BLOCK_SIZE ((size_t)1024*1024)

#define DEBUGINFORMATION std::string(" | from ") + std::string(__FILE__) + std::string(" L") + std::to_string(__LINE__)

class robustFileDatingexception : public std::exception {
    public:
        robustFileDatingexception(std::string const &message, std::string const &component = "robustFileDatingexception")
        : _message(message), _component(component) {};

        std::string const &getComponent() const noexcept { return _component;};
        const char *what() const noexcept {return _message.c_str();};
    private:
        std::string _message;
        std::string _component;
};

void generateRSAKeyPair(std::string const &name) {
    int ret = 0;
    RSA *r = NULL;
	BIGNUM *bne = NULL;
	BIO *bp_public = NULL;
    BIO *bp_private = NULL;
	int bits = 2048;
	unsigned long e = RSA_F4;

    // 1. generate rsa key
	bne = BN_new();
	ret = BN_set_word(bne, e);
    if (ret != 1)
        throw robustFileDatingexception("BN_set_word failed" + DEBUGINFORMATION);

    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if (ret != 1)
        throw robustFileDatingexception("BN_set_word failed" + DEBUGINFORMATION);

    // 2. save public key
    bp_public = BIO_new_file((name + "_public" + ".pem").c_str(), "w+");
	ret = PEM_write_bio_RSAPublicKey(bp_public, r);
    if (ret != 1)
        throw robustFileDatingexception("BN_set_word failed" + DEBUGINFORMATION);

    // 3. save private key
	bp_private = BIO_new_file((name + "_private" + ".pem").c_str(), "w+");
	ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
    if (ret != 1)
        throw robustFileDatingexception("BN_set_word failed" + DEBUGINFORMATION);
    
    // 4. free
    BIO_free_all(bp_public);
	BIO_free_all(bp_private);
	RSA_free(r);
	BN_free(bne);
}

void sha256_hash_string(unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65]) {
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);

    outputBuffer[64] = 0;
}

std::string hash_tostring(unsigned char *hash, unsigned int size) {
    char *buf = new char[size*2 + 1];
    for(unsigned int i = 0; i < size; i++)
        sprintf(buf + (i * 2), "%02x", hash[i]);
    buf[size*2] = 0;
    auto str = std::string(buf);
    delete[] buf;
    return str;
}

unsigned char hex_to_char(unsigned char h1, unsigned char h2) {
    char const * const values = "0123456789abcdef";
    unsigned char res = 0; 
    if (h1 != 0) {
        for (unsigned char i = 0; values[i]; i++) {
            if (values[i] == h1) {
                res |= i*16;
                break;
            }
        }
    }

    for (unsigned char i = 0; values[i]; i++) {
        if (values[i] == h2) {
            res |= i;
            break;
        }
    }
    return res;
}

unsigned char *string_tohash(std::string const &hex_chars) {
    size_t len = hex_chars.length(); 
    unsigned char *bytes = new unsigned char[len/2];
    for (size_t i = 0; i < len; i += 2) {
        bytes[i/2] = hex_to_char(hex_chars[i], hex_chars[i+1]);
    }    
    return bytes;
}

int sha256_file(char *path, unsigned char hash[SHA256_DIGEST_LENGTH]) {
    std::streampos size;
    std::ifstream file(path, std::ios::in | std::ios::binary | std::ios::ate);
    if (!file.is_open()) throw robustFileDatingexception("cannot open file" + DEBUGINFORMATION);

    size = file.tellg();
    file.seekg(0, std::ios::beg);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    char * const buffer = new char[BLOCK_SIZE];
    if(!buffer)  throw robustFileDatingexception("cannot alloc buffer" + DEBUGINFORMATION);
    while (size) {
        size_t readSize = std::min(BLOCK_SIZE, (size_t)size);
        file.read(buffer, readSize);
        size -= readSize;
        SHA256_Update(&sha256, buffer, readSize);
    }
    SHA256_Final(hash, &sha256);

    //sha256_hash_string(hash, outputBuffer);
    file.close();
    delete[] buffer;
    return 0;
}

#define TIME_SIZE sizeof(uint64_t)

int main(int argc, char **argv) {
    auto hashClock = std::chrono::high_resolution_clock::now();
    if (std::string(argv[1]) == std::string("-g") && argc == 3) {
        std::cout << "generate keys: " << argv[2] << std::endl;
        generateRSAKeyPair(std::string(argv[2]));        
    } else if (argc == 3) {
        unsigned char hash[SHA256_DIGEST_LENGTH+TIME_SIZE];
        sha256_file(argv[1], hash);
        std::string const hashStr = hash_tostring(hash, SHA256_DIGEST_LENGTH);
        std::cerr << "fileHash=" << hashStr << std::endl;

        std::string const keyname = "tmp";
        //generateRSAKeyPair(keyname);

        uint64_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::cerr << "time=" << now << std::endl;

        FILE *fp = fopen((argv[2] + std::string("_private.pem")).c_str(), "r");
        if (!fp) throw robustFileDatingexception(std::string("cannot open file ") + argv[2] + DEBUGINFORMATION);
        RSA *rsaPrivate = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
        if (!rsaPrivate) throw robustFileDatingexception(std::string("rsaPrivate ") + argv[2] + DEBUGINFORMATION);
        fclose(fp);
        int rsaPrivateKeySize = RSA_size(rsaPrivate);
        memcpy(hash+SHA256_DIGEST_LENGTH, &now, TIME_SIZE);
        unsigned char *hashCrypted = new unsigned char[rsaPrivateKeySize];
        memset(hashCrypted, 0, rsaPrivateKeySize);
        int rsa_outlen = RSA_private_encrypt(
            SHA256_DIGEST_LENGTH + TIME_SIZE, (unsigned char *)hash, hashCrypted,
            rsaPrivate, RSA_PKCS1_PADDING); // todo add time to key

        
        std::ifstream file((argv[2] + std::string("_public.pem")).c_str(), std::ios::in | std::ios::binary | std::ios::ate);
        if (!file.is_open()) throw robustFileDatingexception("cannot open file" + DEBUGINFORMATION);

        std::streampos size = file.tellg();
        file.seekg(0, std::ios::beg);
        char *rsaPubStr = new char[(size_t)size+1];
        file.read(rsaPubStr, size);
        rsaPubStr[size] = 0;
        {
            int j = 0;
            int i = strlen("-----BEGIN RSA PUBLIC KEY-----");
            for (; rsaPubStr[i]; i++) 
                if (rsaPubStr[i] != '\n')
                    rsaPubStr[j++] = rsaPubStr[i];
            rsaPubStr[j-strlen("-----END RSA PUBLIC KEY-----")] = 0;

        }

        std::string const path = argv[1] + std::string(".date");
        std::ofstream outfile(path.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
        if (!outfile.is_open()) throw robustFileDatingexception("cannot create output file" + DEBUGINFORMATION);

        outfile << "crypt=" << hash_tostring(hashCrypted, rsa_outlen) << std::endl;
        outfile << "rsa_pub=" << rsaPubStr << std::endl;
        //outfile << "time=" << now  << std::endl;
        std::cout << "generated file: " << path << std::endl;

        delete[] rsaPubStr;
        delete[] hashCrypted;


    } else if (argc == 2) {
        // read all .date file
        std::ifstream file((argv[1] + std::string(".date")).c_str(), std::ios::in | std::ios::binary | std::ios::ate);
        if (!file.is_open()) throw robustFileDatingexception("cannot open .date file" + DEBUGINFORMATION);
        std::streampos size = file.tellg();
        file.seekg(0, std::ios::beg);
        char *rfdData = new char[(size_t)size+1];
        file.read(rfdData, size);
        rfdData[size] = 0;
        std::string rfdString(rfdData);
        //

        std::map<std::string, std::string> hashMap;
        size_t offset = 0;
        size_t pos;
        while ((pos = rfdString.find('\n', offset)) != std::string::npos) {
            std::string sub = rfdString.substr(offset, pos-offset);
            if (sub.length() == 0)
                continue;
            hashMap[sub.substr(0, sub.find('=', 0))] = sub.substr(sub.find('=', 0)+1, sub.length());
            offset += sub.length()+1;
        }
        delete[] rfdData;

        // calc file hash
        unsigned char hash[SHA256_DIGEST_LENGTH];
        sha256_file(argv[1], hash);
        std::string const hashStr = hash_tostring(hash, SHA256_DIGEST_LENGTH);
        //

        //std::string tmpPath = hashStr + ".tmp.pem";
        //std::FILE *tmpFile = fopen(tmpPath.c_str(), "w+");
        std::FILE *tmpFile = std::tmpfile();
        if (!tmpFile) throw robustFileDatingexception("cannot crete .tmp file" + DEBUGINFORMATION);
        std::fputs("-----BEGIN RSA PUBLIC KEY-----\n", tmpFile);
        std::fputs(hashMap["rsa_pub"].c_str(), tmpFile);
        std::fputs("\n-----END RSA PUBLIC KEY-----\n", tmpFile);
        std::rewind(tmpFile);
        RSA *rsaPublic = PEM_read_RSAPublicKey(tmpFile, NULL, NULL, NULL);
        if (!rsaPublic) throw robustFileDatingexception("cannot load pub_key" + DEBUGINFORMATION);

        int rsaPublicKeySize = RSA_size(rsaPublic);

        if ((size_t)rsaPublicKeySize != hashMap["crypt"].length()/2) throw robustFileDatingexception("invalid crypted lenght" + DEBUGINFORMATION);

        unsigned char *cryptedBuf = string_tohash(hashMap["crypt"]);

        unsigned char buf[rsaPublicKeySize+1];
        memset(buf, 0, rsaPublicKeySize);
        int rsa_outlen = RSA_public_decrypt(
            rsaPublicKeySize, (unsigned char *)cryptedBuf, (unsigned char *)buf,
            rsaPublic, RSA_PKCS1_PADDING);
        buf[rsa_outlen] = 0;

        uint32_t saveTime;
        memcpy(&saveTime, buf+SHA256_DIGEST_LENGTH, sizeof(saveTime));
        buf[SHA256_DIGEST_LENGTH] = 0;

        bool good = true;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            if (buf[i] != hash[i]) {
                good = false;
                break;
            }
        }
        if (good) {
            std::cout << "last modification date: " << saveTime << std::endl;
        } else {
            std::cout << "!!!file or .date has been modified!!!" << std::endl;
        }
        delete[] cryptedBuf;

    }
    double totTs = std::chrono::duration<double, std::ratio<1, 1>>(std::chrono::high_resolution_clock::now()-hashClock).count();
    std::cerr << "END " << totTs << "s" << std::endl;
}