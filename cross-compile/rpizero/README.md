### Cross Compiling

1. Get a cross compiler: You can find a pre-compiled Raspberry Pi cross compiler for Linux [here](https://github.com/abhiTronix/raspberry-pi-cross-compilers).

2. Set the cross compiler path in `RaspberryPi.cmake`

3. Go to the root folder and copy paste the whole command:

   ```
   rm -rf build; cmake -DCMAKE_TOOLCHAIN_FILE=cross-compile/rpizero/RaspberryPi.cmake -B build; cmake --build build
   ```

   

