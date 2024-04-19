#include <vector>
#include <sstream>

#define MAKE_TEST_ID(x) (0xEF | x<<24) 

#define SHA256_HASH_BUFF_SIZE   32


class Se050Middleware {
public:
    Se050Middleware(int key_id = 1024) : mkey_id{key_id}{}
    ~Se050Middleware(){}
    void init_interface();
    void init_interface(int sda, int scl);
    void generate_key_pair_nistp256();
    std::vector<uint8_t> sign_sha256_digest(const std::vector<uint8_t>& digest);
    std::vector<uint8_t> calculate_sha256(std::vector<uint8_t>& payload);
    std::vector<uint8_t> generate_random_number(size_t size = 32);
    void delete_obj(size_t objId);
    void print_hex_buffer(const std::vector<uint8_t>& hexBuff);
    int write_binary_data(size_t objId, const std::vector<uint8_t>& payload);
    std::vector<uint8_t> read_binary_data(size_t objId, size_t dataLen);
    void write_error_msg(const char* msg);
    void read_error_msg(char* msg);
    std::ostringstream oss;

private:
    int32_t mkey_id;
};

extern Se050Middleware se050_obj; 