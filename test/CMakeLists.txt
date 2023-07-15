cmake_minimum_required(VERSION 3.16)
project(se050_test)

set(CMAKE_CXX_STANDARD 17)

# Add the test.cpp file as a separate executable
add_executable(${PROJECT_NAME} test.cpp)

# Include the main project's header files (optional, if needed for testing)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../platform/)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../T1oI2C/)
