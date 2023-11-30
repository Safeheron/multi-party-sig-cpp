add_subdirectory(multi-party-sig/mpc-flow)
add_subdirectory(multi-party-sig/multi-party-ecdsa)

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # depend on pkg-config, this looks for opencv.pc file

#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

find_package(SafeheronCryptoSuites REQUIRED)

target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE /usr/local/lib)
target_link_libraries(${CMAKE_PROJECT_NAME}
        ${PROTOBUF_LIBRARIES}
        OpenSSL::Crypto
        -ldl
        SafeheronCryptoSuites
        )