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

/*void writeheader(char fileHash[65], uint64_t time, std::string keyFile) {
    FILE *fp = fopen(private_key_file_name, "r");

    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);

    fclose(fp);
    
    std::cout << fileHash << ":" << fileName << ":" << time << std::endl;
}*/

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
            for (int i = 0; rsaPubStr[i]; i++) 
                if (rsaPubStr[i] != '\n')
                    rsaPubStr[j++] = rsaPubStr[i];
            rsaPubStr[j] = 0;
        }

        std::string const path = argv[1] + std::string(".date");
        std::ofstream outfile(path.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
        if (!outfile.is_open()) throw robustFileDatingexception("cannot create output file" + DEBUGINFORMATION);

        outfile << "crypt=" << hash_tostring(hashCrypted, rsa_outlen) << std::endl;
        outfile << "rsa_pub=" << rsaPubStr << std::endl;
        outfile << "time=" << now  << std::endl;
        std::cout << "generated file: " << path << std::endl;

        delete[] rsaPubStr;
        delete[] hashCrypted;


        //FILE *fp2 = fopen((argv[2] + std::string("_public.pem")).c_str(), "r");
        //if (!fp2) throw robustFileDatingexception(std::string("cannot open file ") + argv[2] + DEBUGINFORMATION);
        //RSA *rsaPublic = PEM_read_RSAPublicKey(fp2, NULL, NULL, NULL);
        //if (!rsaPublic) throw robustFileDatingexception(std::string("rsaPublic ") + argv[2] + DEBUGINFORMATION);
        //fclose(fp2);
        //int rsaPublicKeySize = RSA_size(rsaPublic);
        /*char buf[257];

        rsa_outlen = RSA_public_decrypt(
            rsa_outlen, (unsigned char *)hashCrypted, (unsigned char *)buf,
            rsaPrivate, RSA_PKCS1_PADDING);
        buf[rsa_outlen] = 0;




        //writeheader(buf, now);*/
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
        std::cout << rfdData << std::endl;
        //

        std::map<std::string, std::string> hashMap;
        size_t offset = 0;
        size_t pos;
        while ((pos = rfdString.find('\n', offset)) != std::string::npos) {
            std::string sub = rfdString.substr(offset, pos);
            std::cout << offset << " : " << sub << std::endl;
            offset += sub.length();
        }


        // calc file hash
        unsigned char hash[SHA256_DIGEST_LENGTH];
        sha256_file(argv[1], hash);
        std::string const hashStr = hash_tostring(hash, SHA256_DIGEST_LENGTH);
        std::cerr << "fileHash=" << hashStr << std::endl;
        //



        delete[] rfdData;
    }
    double totTs = std::chrono::duration<double, std::ratio<1, 1>>(std::chrono::high_resolution_clock::now()-hashClock).count();
    std::cerr << "END " << totTs << "s" << std::endl;
}