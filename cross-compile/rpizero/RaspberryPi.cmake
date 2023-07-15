SET(CMAKE_SYSTEM_NAME Linux)
SET(CMAKE_SYSTEM_VERSION 1)

# specify the cross compiler
SET(CMAKE_C_COMPILER /home/$ENV{USER}/toolchains/cross-pi-gcc-10.3.0-0/bin/arm-linux-gnueabihf-gcc)
SET(CMAKE_CXX_COMPILER /home/$ENV{USER}/toolchains/cross-pi-gcc-10.3.0-0/bin/arm-linux-gnueabihf-g++)

# search for programs in the build host directories
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# for libraries and headers in the target directories
set(CMAKE_TARGET_NAME "rpizero")
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_LIBRARY_PATH ${PROJECT_SOURCE_DIR}/cross-compile/rpizero/lib/)
set(RPI_LIB_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/cross-compile/rpizero/inc/ CACHE PATH ${PROJECT_SOURCE_DIR}/cross-compile/rpizero/inc/)