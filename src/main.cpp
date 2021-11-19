#include <iostream>
#include <vector>
#include <fstream>
#include <chrono>
#include <exception>
#include <filesystem>
#include <algorithm>
#include <map>
#include <string>

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <mutex>
#include <thread>

#include <cmath>

#if __WIN32__
#define stat64 _stat64
#endif

#define THREAD_COUNT 7

#define BLOCK_SIZE ((size_t)1024*1024)

#define DEBUGINFORMATION std::string(" | from ") + std::string(__FILE__) + std::string(" L") + std::to_string(__LINE__)

#define TIME_SIZE sizeof(uint64_t)

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

#define PBSTR "||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
#define PBWIDTH 60

void printProgress(double percentage) {
    float val = (percentage * 100);
    percentage = std::min(percentage, 1.0);
    int lpad = (int) (percentage * PBWIDTH);
    int rpad = PBWIDTH - lpad;
    printf("\r%3f2%% [%.*s%*s]", val, lpad, PBSTR, rpad, "");
    fflush(stdout);
}

long int fsize(const char *filename) {
    struct stat st; 

    if (stat(filename, &st) == 0) {
        std::cout << filename << " : " << st.st_size << std::endl;
        return st.st_size;
    }
    return -1; 
}

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
    std::FILE *tmpFile = fopen(path, "r+");
    if (!tmpFile) throw robustFileDatingexception(std::string("cannot open file: ") + path + DEBUGINFORMATION);
    fclose(tmpFile);
    std::ifstream file(path, std::ios::in | std::ios::binary | std::ios::ate);
    if (!file.is_open()) throw robustFileDatingexception("cannot open file" + DEBUGINFORMATION);

    long int size = fsize(path);
    long int size_back = size;
    if (size == -1) throw robustFileDatingexception("cannot find file size" + DEBUGINFORMATION);
    file.seekg(0, std::ios::beg);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    char * const buffer = new char[BLOCK_SIZE];
    if(!buffer)  throw robustFileDatingexception("cannot alloc buffer" + DEBUGINFORMATION);
    while (size) {
        printProgress(1-(double)size/size_back);
        size_t readSize = std::min(BLOCK_SIZE, (size_t)size);
        file.read(buffer, readSize);
        size -= readSize;
        SHA256_Update(&sha256, buffer, readSize);
    }
    printProgress(1-(double)size/size_back);
    std::cout << std::endl;
    SHA256_Final(hash, &sha256);

    //sha256_hash_string(hash, outputBuffer);
    file.close();
    delete[] buffer;
    return 0;
}

class KeyFinder {
public:
    KeyFinder(uint thread_count, char *str) :
        _thread_count(thread_count), _str(str)
    {

    }

    ~KeyFinder() {

    }

    RSA *find() {
        for (uint i = 0; i < _thread_count; i++) {
            char *str = strdup(_str);
            _threads.emplace_back(std::thread(
                [i, str, this](){
                    this->find_a_key(str, i);
                }
            ));
        }

        for (auto &thread : _threads)
            thread.join();
        return _ret;
    }

    void find_a_key(char *str, int id) {

        char *rsaPubStr = new char[1024*1024];
        BIO * keybio = BIO_new(BIO_s_mem());
        int ret = 0;
        RSA *rsa = NULL;
        BIGNUM *bne = NULL;
        int bits = 512;
        unsigned long e = RSA_F4;

        bne = BN_new();
        ret = BN_set_word(bne, e);
        if (ret != 1)
            throw robustFileDatingexception("BN_set_word failed" + DEBUGINFORMATION);
        long int proba = std::pow(64, strlen(str))/55;
        long int count = 0;

        while (1) {
            rsa = RSA_new();
            ret = RSA_generate_key_ex(rsa, bits, bne, NULL);
            if (ret != 1)
                throw robustFileDatingexception("RSA_generate_key_ex failed" + DEBUGINFORMATION);

            PEM_write_bio_RSAPublicKey(keybio, rsa);
            std::string res = "";
            memset(rsaPubStr, 0, 1024*1024);
            BIO_read(keybio, rsaPubStr, 1024*1024);
            {
                int j = 0;
                int i = strlen("-----BEGIN RSA PUBLIC KEY-----");
                for (; rsaPubStr[i]; i++) 
                    if (rsaPubStr[i] != '\n')
                        rsaPubStr[j++] = rsaPubStr[i];
                rsaPubStr[j-strlen("-----END RSA PUBLIC KEY-----")] = 0;
            }

            if (strstr(rsaPubStr, str)) {
                std::lock_guard<std::mutex> lock(_mutex);
                _go = false;
                _ret = rsa;
                std::cout << rsaPubStr << std::endl;
            }
            //std::cout << "ici" << count << " id="<< id << std::endl;
            { // end condition
                std::lock_guard<std::mutex> lock(_mutex);
                _count++;
                if (!(count % 50) && id == 0) {
                    printProgress((float)_count/proba);
                    std::cout << " " << _count << "/" << proba;
                }
                if (!_go)
                    break;
            }
            count++;
        }
    }

    bool _go = true;
    uint64_t _count = 0;
    std::vector<std::thread> _threads;
    std::mutex _mutex;
    uint _thread_count;
    RSA *_ret = 0;
    char *_str;
};



int main(int argc, char **argv) {
    int returnValue = 0;
    auto hashClock = std::chrono::high_resolution_clock::now();
    if (std::string(argv[1]) == std::string("-g") && (argc == 3 || argc == 4)) {
        std::cout << "generate keys: " << argv[2] << std::endl;
        if (argc == 4) {
            
            KeyFinder finder(THREAD_COUNT, argv[3]);
            RSA *rsa = finder.find();
            
            BIO * keybio = BIO_new(BIO_s_mem());
            int ret = 0;

            /*exit(0);

            char *rsaPubStr = new char[1024*1024];
            RSA *rsa = NULL;
            BIGNUM *bne = NULL;
            int bits = 512;
            unsigned long e = RSA_F4;

            bne = BN_new();
            ret = BN_set_word(bne, e);
            if (ret != 1)
                throw robustFileDatingexception("BN_set_word failed" + DEBUGINFORMATION);
            long int proba = std::pow(64, strlen(argv[3]))/55;
            long int count = 0;
            do {
                rsa = RSA_new();
                ret = RSA_generate_key_ex(rsa, bits, bne, NULL);
                if (ret != 1)
                    throw robustFileDatingexception("RSA_generate_key_ex failed" + DEBUGINFORMATION);

                PEM_write_bio_RSAPublicKey(keybio, rsa);
                std::string res = "";
                memset(rsaPubStr, 0, 1024*1024);
                BIO_read(keybio, rsaPubStr, 1024*1024);
                {
                    int j = 0;
                    int i = strlen("-----BEGIN RSA PUBLIC KEY-----");
                    for (; rsaPubStr[i]; i++) 
                        if (rsaPubStr[i] != '\n')
                            rsaPubStr[j++] = rsaPubStr[i];
                    rsaPubStr[j-strlen("-----END RSA PUBLIC KEY-----")] = 0;
                }
                if (!(count % 100)) {
                    printProgress((float)count/proba);
                    std::cout << " " << count << "/" << proba;
                }
                count++;
            } while (!strstr(rsaPubStr, argv[3]));
            //} while (strncmp(rsaPubStr, argv[3], strlen(argv[3])));*/

            // 2. save public key
            std::string name = argv[2];
            keybio = BIO_new_file((name + "_public" + ".pem").c_str(), "w+");
            ret = PEM_write_bio_RSAPublicKey(keybio, rsa);
            if (ret != 1)
                throw robustFileDatingexception("BN_set_word failed" + DEBUGINFORMATION);

            // 3. save private key
            keybio = BIO_new_file((name + "_private" + ".pem").c_str(), "w+");
            ret = PEM_write_bio_RSAPrivateKey(keybio, rsa, NULL, NULL, 0, NULL, NULL);
            if (ret != 1)
                throw robustFileDatingexception("BN_set_word failed" + DEBUGINFORMATION);

        } else 
            generateRSAKeyPair(std::string(argv[2]));
    } else if (argc >= 3) {

        FILE *fp = fopen((argv[1] + std::string("_private.pem")).c_str(), "r+");
        if (!fp) throw robustFileDatingexception(std::string("cannot open file ") + (argv[1] + std::string("_private.pem")) + DEBUGINFORMATION);
        RSA *rsaPrivate = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
        if (!rsaPrivate) throw robustFileDatingexception(std::string("rsaPrivate ") + argv[1] + DEBUGINFORMATION);
        fclose(fp);
        int rsaPrivateKeySize = RSA_size(rsaPrivate);

        for (int i = 0; i < argc - 2; i++) {
            int fileid = i + 2;
            std::cout << "dating " << argv[fileid] << " with " << argv[1] << std::endl;
            unsigned char hash[SHA256_DIGEST_LENGTH+TIME_SIZE];
            sha256_file(argv[fileid], hash);
            std::string const hashStr = hash_tostring(hash, SHA256_DIGEST_LENGTH);
            std::cerr << "fileHash=" << hashStr << std::endl;

            std::string const keyname = "tmp";
            //generateRSAKeyPair(keyname);

            uint64_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            std::cerr << "time=" << now << std::endl;



            memcpy(hash+SHA256_DIGEST_LENGTH, &now, TIME_SIZE);
            unsigned char *hashCrypted = new unsigned char[rsaPrivateKeySize];
            memset(hashCrypted, 0, rsaPrivateKeySize);
            int rsa_outlen = RSA_private_encrypt(
                SHA256_DIGEST_LENGTH + TIME_SIZE, (unsigned char *)hash, hashCrypted,
                rsaPrivate, RSA_PKCS1_PADDING); // todo add time to key

            std::string path2 = (argv[1] + std::string("_public.pem"));
            std::ifstream file(path2.c_str(), std::ios::in | std::ios::binary | std::ios::ate);
            if (!file.is_open()) throw robustFileDatingexception("cannot open file" + DEBUGINFORMATION);

            long int size = fsize(path2.c_str());
            if (size == -1) throw robustFileDatingexception("cannot find file size" + DEBUGINFORMATION);


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

            std::string const path = argv[fileid] + std::string(".date");
            std::ofstream outfile(path.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
            if (!outfile.is_open()) throw robustFileDatingexception("cannot create output file" + DEBUGINFORMATION);

            outfile << "crypt=" << hash_tostring(hashCrypted, rsa_outlen) << std::endl;
            outfile << "rsa_pub=" << rsaPubStr << std::endl;
            //outfile << "time=" << now  << std::endl;
            std::cout << "generated file: " << path << std::endl;

            delete[] rsaPubStr;
            delete[] hashCrypted;
        }


    } else if (argc == 2) {
        // read all .date file
        std::string path1 = argv[1] + std::string(".date");
        std::ifstream file(path1.c_str(), std::ios::in | std::ios::binary | std::ios::ate);
        if (!file.is_open()) throw robustFileDatingexception("cannot open .date file" + DEBUGINFORMATION);
        long int size = fsize(path1.c_str());
        if (size == -1) throw robustFileDatingexception("cannot open .date file" + DEBUGINFORMATION);

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

        //unsigned char buf[rsaPublicKeySize+1];
        unsigned char *buf = new unsigned char[rsaPublicKeySize+1];
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
            std::cout << "signature date: " << saveTime << std::endl;
        } else {
            std::cout << "!!!file or .date has been modified!!!" << std::endl;
            returnValue = 84;
        }
        delete[] cryptedBuf;
    }
    double totTs = std::chrono::duration<double, std::ratio<1, 1>>(std::chrono::high_resolution_clock::now()-hashClock).count();
    std::cerr << "END " << totTs << "s" << std::endl;
    return returnValue;
}