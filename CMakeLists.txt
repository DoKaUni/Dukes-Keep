cmake_minimum_required(VERSION 3.14)

# Set project name, version and languages here. (change as needed)
# Version numbers are available by including "exampleConfig.h" in
# the source. See exampleConfig.h.in for some more details.
project(DUKES_KEEP VERSION 0.1.0.0 LANGUAGES CXX)

# Options: Things you can set via commandline options to cmake (e.g. -DENABLE_LTO=[ON|OFF])
option(ENABLE_WARNINGS_SETTINGS "Allow target_set_warnings to add flags and defines.
                                 Set this to OFF if you want to provide your own warning parameters." ON)
option(ENABLE_LTO "Enable link time optimization" ON)
option(ENABLE_DOCTESTS "Include tests in the library. Setting this to OFF will remove all doctest related code.
                        Tests in tests/*.cpp will still be enabled." ON)

# Include stuff. No change needed.
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
include(ConfigSafeGuards)
include(Colors)
include(CTest)
include(Doctest)
include(LTO)
include(Misc)
include(Warnings)

# Check for LTO support.
find_lto(CXX)

# --------------------------------------------------------------------------------
# Find SDL2 and Vulkan
# --------------------------------------------------------------------------------

find_package(SDL2 REQUIRED)
find_package(Vulkan REQUIRED)
set(OPENSSL_USE_STATIC_LIBS TRUE)  # Force static linking
find_package(LibreSSL REQUIRED SSL Crypto)

# Include SDL2 and Vulkan headers
include_directories(${SDL2_INCLUDE_DIRS})
include_directories(${Vulkan_INCLUDE_DIRS})
include_directories(${OpenSSL_INCLUDE_DIRS})
include_directories(${SQLCIPHER_DIR})

# --------------------------------------------------------------------------------
# Locate files (change as needed).
# --------------------------------------------------------------------------------
set(SOURCES          # All .cpp files in src/
    src/database.cpp
    src/encryption.cpp
    src/fileUtils.cpp
    src/generation.cpp
    src/initialization.cpp
    src/keystore.cpp
    src/pasting.cpp
    src/sections.cpp
)

set(TESTFILES        # All .cpp files in tests/
    tests/main.cpp
)
set(LIBRARY_NAME engine)

# --------------------------------------------------------------------------------
# Add Dear ImGui
# --------------------------------------------------------------------------------
set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/thirdparty/imgui)
include_directories(${IMGUI_DIR} ${IMGUI_DIR}/backends)

# List of ImGui source files
set(IMGUI_SOURCES
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_sdl2.cpp
    ${IMGUI_DIR}/backends/imgui_impl_vulkan.cpp
)

# Combine all sources
set(SOURCES ${SOURCES} ${IMGUI_SOURCES})

# --------------------------------------------------------------------------------
# Build! (Change as needed)
# --------------------------------------------------------------------------------
# Compile all sources into a library.
add_library(${LIBRARY_NAME} OBJECT ${SOURCES})

# Lib needs its header files, and users of the library must also see these (PUBLIC). (No change needed)
target_include_directories(${LIBRARY_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include)

# There's also (probably) doctests within the library, so we need to see this as well.
target_link_libraries(${LIBRARY_NAME} PUBLIC doctest)

# Link external libraries
target_link_libraries(${LIBRARY_NAME} PUBLIC SDL2::SDL2 Vulkan::Vulkan LibreSSL::SSL LibreSSL::Crypto ${SQLCIPHER_LIBRARY})

target_set_warnings(${LIBRARY_NAME} ENABLE ALL AS_ERROR ALL DISABLE Annoying)
# target_compile_options(${LIBRARY_NAME} ... )  # For setting manually.

# Apply the warning suppression flag only to the ImGui Vulkan/SDL2 backend files.
set_source_files_properties(
    ${IMGUI_DIR}/backends/imgui_impl_vulkan.cpp
    ${IMGUI_DIR}/backends/imgui_impl_sdl2.cpp
    PROPERTIES COMPILE_OPTIONS "-Wno-error=class-memaccess"
)

# Add an executable for the file app/main.cpp.
add_executable(main app/main.cpp)
target_link_libraries(main PRIVATE ${LIBRARY_NAME} SDL2::SDL2 Vulkan::Vulkan LibreSSL::SSL LibreSSL::Crypto crypt32 ws2_32 advapi32)

# target_set_warnings(main ENABLE ALL AS_ERROR ALL DISABLE Annoying) # Set warnings (if needed).
target_enable_lto(main optimized)  # enable link-time-optimization if available for non-debug configurations

# Set the properties you require, e.g. what C++ standard to use. Here applied to library and main (change as needed).
set_target_properties(
    ${LIBRARY_NAME} main
      PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO
      OUTPUT_NAME "Duke's Keep"
)

# Set up tests (see tests/CMakeLists.txt).
add_subdirectory(tests)