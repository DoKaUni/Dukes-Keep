# Building from Source
This guide covers how to build **Duke's Keep** from source, including dependencies like Vulkan, SDL2, LibreSSL, and SQLCipher.  
#### Tested on:
* Windows 10 (64-bit) with MinGW and MSVC

## Prerequisites
   - [Git](https://git-scm.com/)  
   - [CMake](https://cmake.org/) (≥3.14)  
   - [Tcl/Tk](https://www.magicsplat.com/tcl-installer/) (for SQLCipher)  
   - C/C++ Compiler (Supporting at least C++11)

## Step 1: Install Dependencies

### 1. Vulkan SDK

#### Windows:
* Download the installer from [vulkan.lunarg.com](https://vulkan.lunarg.com/sdk/home#windows).  
* Run the installer (**SDL2** can also be installed).  

### 2. SDL2

#### Windows:
* Option to be installed with Vulkan SDK installer
* Build from source:
```
git clone https://github.com/libsdl-org/SDL.git -b SDL2
cd SDL
mkdir build
cd build
cmake -G "MinGW Makefiles" ..
cmake --build .
```

### 3. LibreSSL
#### Windows:
   ```
   git clone https://github.com/libressl-portable/portable.git
   cd portable
   mkdir build
   cd build
   cmake -G "MinGW Makefiles" ..
   cmake --build .
   ```
**Post-build**: Copy these files to `libs/` in the build folder:  
     - From `build/crypto/.libs/`:  
       `libcrypto.a`, `libcrypto.dll.a`, `libcrypto-56.dll`  
     - From `build/ssl/.libs/`:  
       `libssl.a`, `libssl.dll.a`, `libssl-59.dll`  

### 4. **SQLCipher** (Build from Source)

#### Windows:
1. Edit `Makefile.msc`:  
   - **Line 1049**: Replace:  
     ```makefile
     TCC = $(TCC) -DSQLITE_TEMP_STORE=1
     ```  
     With:  
     ```makefile
     TCC = $(TCC) -DSQLITE_TEMP_STORE=2 -DSQLITE_HAS_CODEC -I"Drive:\Path\To\LibreSSL\build\include"
     ```  
   - **Between lines 1269–1270**, add:  
     ```makefile
     LTLIBPATHS = $(LTLIBPATHS) /LIBPATH:"Drive:\Path\To\LibreSSL\build\libs"
     LTLIBS = $(LTLIBS) libcrypto.dll.a libssl.dll.a ws2_32.lib shell32.lib advapi32.lib gdi32.lib user32.lib crypt32.lib
     ```  

2. Open *x64 Native Tools Command Prompt* for Visual Studio:  
   ```
   cd Drive:\Path\To\SQLCipher
   nmake /f Makefile.msc
   ```

## Step 2: Build Duke's Keep
1. Clone the repository:  
   ```bash
   git clone git clone --recurse-submodules https://github.com/DoKaUni/Dukes-Keep.git
   cd Dukes-Keep
   ```  
2. Create a toolchain:\
toolchain.cmake:
```
set(SDL2_DIR "Drive:/path/to/VulkanSDK/cmake)
set(LIBRESSL_ROOT_DIR "Drive:/path/to/LibreSSL/build)
set(CMAKE_MODULE_PATH "${LIBRESSL_ROOT_DIR} ${CMAKE_MODULE_PATH})
set(SQLCIPHER_DIR "Drive:/path/to/SQLcipher)
set(SQLCIPHER_LIBRARY "${SQLCIPHER_DIR}/sqlite3.lib")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mwindows -DSQLITE_HAS_CODEC)

set(CMAKE_PREFIX_PATH ${SDL2_DIR} ${LIBRESSL_ROOT_DIR} ${SQLCIPHER_DIR})

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-subsystem,console")
```
You can add your own various flags. `-Wl,-subsystem,console` should only be used for debugging.

3. Configure with CMake:  
   ```bash
   mkdir build
   cd build
   cmake -G "MinGW Makefiles" -DCMAKE_TOOLCHAIN_FILE=path/to/toolchain/toolchain.cmake ..
   ```
4. Compile:  
   ```bash
   cmake --build .
   ```
5. Adding library DLLs
* Copy `sqlite3.ddl` from your sqlcipher directory to the Duke's Keep build directory
* Copy `libcrypto-56.dll` and `libssl-59.dll` from LibreSSL's `build/libs` or `build/ssl/.libs` to the Duke's Keep build directory

## Troubleshooting
- **LibreSSL/SQLCipher linkage errors**: Ensure paths in `Makefile.msc` or your toolchain are correct.  
- **Missing DLLs**: Copy `sqlite3.ddl`, `libcrypto-56.dll` and `libssl-59.dll` to the binary folder.  
