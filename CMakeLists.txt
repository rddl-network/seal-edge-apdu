cmake_minimum_required(VERSION 3.16)
project(se050_apdu)
set(CMAKE_CXX_STANDARD 17)

if(NOT CMAKE_TARGET_NAME)
    set(CMAKE_TARGET_NAME "esp")
endif()

# Create the library target for se050_apdu
add_library(se050_apdu STATIC
    se050_middleware.cpp apdu.c platform/${CMAKE_TARGET_NAME}/i2c.c platform/${CMAKE_TARGET_NAME}/reset.c
    T1oI2C/phNxpEse_Api.c T1oI2C/phNxpEseProto7816_3.c T1oI2C/phNxpEsePal_i2c.c
)

target_include_directories(se050_apdu PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/platform/)
target_include_directories(se050_apdu PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/T1oI2C/)

# Create the executable target for se050_test
add_executable(se050_test test/test.cpp)

# Link se050_test against se050_apdu library
target_link_libraries(se050_test PRIVATE se050_apdu)
