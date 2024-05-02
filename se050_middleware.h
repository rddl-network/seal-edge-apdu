#include <vector>
#include <sstream>

#define MAKE_TEST_ID(x) (0xEF | x<<24) 

#define SHA256_HASH_BUFF_SIZE   32


class Se050Middleware {
public:
    Se050Middleware(uint32_t key_id = 1024) : mkey_id{key_id}{}
    ~Se050Middleware(){}
    void init_interface();
    void init_interface(int sda, int scl);
    void generate_key_pair_nistp256();
    std::vector<uint8_t> sign_sha256_digest(const std::vector<uint8_t>& digest);
    bool verify_sha256_digest(const std::vector<uint8_t>& digest, const std::vector<uint8_t> signature, const std::vector<uint8_t> pubKey = std::vector<uint8_t>{});
    std::vector<uint8_t> calculate_sha256(std::vector<uint8_t>& payload);
    std::vector<uint8_t> generate_random_number(size_t size = 32);
    void delete_obj(uint32_t objId);
    void print_hex_buffer(const std::vector<uint8_t>& hexBuff);
    int write_binary_data(uint32_t objId, const std::vector<uint8_t>& payload);
    std::vector<uint8_t> read_binary_data(uint32_t objId, size_t dataLen);
    void write_error_msg(const char* msg);
    void read_error_msg(char* msg);
    bool check_obj_exist(uint32_t objId);
    std::vector<uint8_t> get_public_key();
    std::ostringstream oss;
    uint32_t get_key_id(){return mkey_id;}

private:
    uint32_t mkey_id;
};

extern Se050Middleware se050_obj; 