add_subdirectory(mpc-flow)
add_subdirectory(multi-party-ecdsa)

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # depend on pkg-config, this looks for opencv.pc file

#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

find_package(SafeheronCryptoSuites REQUIRED)
find_package(MPCFlow REQUIRED)

target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC
        ${PROTOBUF_INCLUDE_DIRS}
        /usr/local/include
        ${MPCFlow_INCLUDE_DIRS}
        ${SafeheronCryptoSuites_INCLUDE_DIRS}
        )

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        ${OPENSSL_INCLUDE_DIR}
        )

target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE /usr/local/lib)
target_link_libraries(${CMAKE_PROJECT_NAME}
        ${PROTOBUF_LIBRARIES}
        OpenSSL::Crypto
        -ldl
        MPCFlow
        SafeheronCryptoSuites
        )