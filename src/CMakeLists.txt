file(GLOB gg18_common_SOURCE
        multi-party-ecdsa/gg18/proto_gen/struct.pb.switch.cc
        multi-party-ecdsa/gg18/util.cpp
        multi-party-ecdsa/gg18/party_local.cpp
        multi-party-ecdsa/gg18/party_remote.cpp
        multi-party-ecdsa/gg18/sign_key.cpp
        )

file(GLOB gg18_key_gen_SOURCE
        multi-party-ecdsa/gg18/key_gen/context.cpp
        multi-party-ecdsa/gg18/key_gen/proto_gen/key_gen.pb.switch.cc
        multi-party-ecdsa/gg18/key_gen/round0_bc_message.cpp
        multi-party-ecdsa/gg18/key_gen/round1_bc_message.cpp
        multi-party-ecdsa/gg18/key_gen/round1_p2p_message.cpp
        multi-party-ecdsa/gg18/key_gen/round2_bc_message2.cpp
        multi-party-ecdsa/gg18/key_gen/round0.cpp
        multi-party-ecdsa/gg18/key_gen/round1.cpp
        multi-party-ecdsa/gg18/key_gen/round2.cpp
        multi-party-ecdsa/gg18/key_gen/round3.cpp
        multi-party-ecdsa/gg18/key_gen/t_party.cpp
        )

file(GLOB gg18_key_refresh_SOURCE
        multi-party-ecdsa/gg18/key_refresh/context.cpp
        multi-party-ecdsa/gg18/key_refresh/proto_gen/key_refresh.pb.switch.cc
        multi-party-ecdsa/gg18/key_refresh/round0_bc_message.cpp
        multi-party-ecdsa/gg18/key_refresh/round1_p2p_message.cpp
        multi-party-ecdsa/gg18/key_refresh/round1_bc_message.cpp
        multi-party-ecdsa/gg18/key_refresh/round2_p2p_message.cpp
        multi-party-ecdsa/gg18/key_refresh/round3_bc_message.cpp
        multi-party-ecdsa/gg18/key_refresh/round0.cpp
        multi-party-ecdsa/gg18/key_refresh/round1.cpp
        multi-party-ecdsa/gg18/key_refresh/round2.cpp
        multi-party-ecdsa/gg18/key_refresh/round3.cpp
        multi-party-ecdsa/gg18/key_refresh/round4.cpp
        multi-party-ecdsa/gg18/key_refresh/t_party.cpp
        )

file(GLOB gg18_sign_SOURCE
        multi-party-ecdsa/gg18/sign/context.cpp
        multi-party-ecdsa/gg18/sign/round0.cpp
        multi-party-ecdsa/gg18/sign/round1.cpp
        multi-party-ecdsa/gg18/sign/round2.cpp
        multi-party-ecdsa/gg18/sign/round3.cpp
        multi-party-ecdsa/gg18/sign/round4.cpp
        multi-party-ecdsa/gg18/sign/round5.cpp
        multi-party-ecdsa/gg18/sign/round6.cpp
        multi-party-ecdsa/gg18/sign/round7.cpp
        multi-party-ecdsa/gg18/sign/round8.cpp
        multi-party-ecdsa/gg18/sign/round9.cpp
        multi-party-ecdsa/gg18/sign/round0_bc_message.cpp
        multi-party-ecdsa/gg18/sign/round0_p2p_message.cpp
        multi-party-ecdsa/gg18/sign/round1_p2p_message.cpp
        multi-party-ecdsa/gg18/sign/round2_bc_message.cpp
        multi-party-ecdsa/gg18/sign/round3_bc_message.cpp
        multi-party-ecdsa/gg18/sign/round4_bc_message.cpp
        multi-party-ecdsa/gg18/sign/round5_bc_message.cpp
        multi-party-ecdsa/gg18/sign/round6_bc_message.cpp
        multi-party-ecdsa/gg18/sign/round7_bc_message.cpp
        multi-party-ecdsa/gg18/sign/round8_bc_message.cpp
        multi-party-ecdsa/gg18/sign/party_local.cpp
        multi-party-ecdsa/gg18/sign/party_remote.cpp
        multi-party-ecdsa/gg18/sign/t_party.cpp
        multi-party-ecdsa/gg18/sign/mta.cpp
        multi-party-ecdsa/gg18/sign/proto_gen/sign.pb.switch.cc
        )

file(GLOB gg20_sign_SOURCE
        multi-party-ecdsa/gg20/sign/context.cpp
        multi-party-ecdsa/gg20/sign/round0.cpp
        multi-party-ecdsa/gg20/sign/round1.cpp
        multi-party-ecdsa/gg20/sign/round2.cpp
        multi-party-ecdsa/gg20/sign/round3.cpp
        multi-party-ecdsa/gg20/sign/round4.cpp
        multi-party-ecdsa/gg20/sign/round5.cpp
        multi-party-ecdsa/gg20/sign/round6.cpp
        multi-party-ecdsa/gg20/sign/round7.cpp
        multi-party-ecdsa/gg20/sign/round0_p2p_message.cpp
        multi-party-ecdsa/gg20/sign/round0_bc_message.cpp
        multi-party-ecdsa/gg20/sign/round1_p2p_message.cpp
        multi-party-ecdsa/gg20/sign/round2_bc_message.cpp
        multi-party-ecdsa/gg20/sign/round3_bc_message.cpp
        multi-party-ecdsa/gg20/sign/round4_bc_message.cpp
        multi-party-ecdsa/gg20/sign/round4_p2p_message.cpp
        multi-party-ecdsa/gg20/sign/round5_bc_message.cpp
        multi-party-ecdsa/gg20/sign/round6_bc_message.cpp
        multi-party-ecdsa/gg20/sign/t_party.cpp
        multi-party-ecdsa/gg20/sign/proto_gen/sign.pb.switch.cc
        )

file(GLOB cmp_common_SOURCE
        multi-party-ecdsa/cmp/proto_gen/struct.pb.switch.cc
        multi-party-ecdsa/cmp/util.cpp
        multi-party-ecdsa/cmp/party_param.cpp
        multi-party-ecdsa/cmp/party_local.cpp
        multi-party-ecdsa/cmp/party_remote.cpp
        multi-party-ecdsa/cmp/sign_key.cpp
        multi-party-ecdsa/cmp/minimal_party_param.cpp
        multi-party-ecdsa/cmp/minimal_party_local.cpp
        multi-party-ecdsa/cmp/minimal_party_remote.cpp
        multi-party-ecdsa/cmp/minimal_sign_key.cpp
        )

file(GLOB cmp_minimal_key_gen_SOURCE
        multi-party-ecdsa/cmp/minimal_key_gen/context.cpp
        multi-party-ecdsa/cmp/minimal_key_gen/proto_gen/minimal_key_gen.pb.switch.cc
        multi-party-ecdsa/cmp/minimal_key_gen/round0_bc_message.cpp
        multi-party-ecdsa/cmp/minimal_key_gen/round1_p2p_message.cpp
        multi-party-ecdsa/cmp/minimal_key_gen/round1_bc_message.cpp
        multi-party-ecdsa/cmp/minimal_key_gen/round2_bc_message.cpp
        multi-party-ecdsa/cmp/minimal_key_gen/round0.cpp
        multi-party-ecdsa/cmp/minimal_key_gen/round1.cpp
        multi-party-ecdsa/cmp/minimal_key_gen/round2.cpp
        multi-party-ecdsa/cmp/minimal_key_gen/round3.cpp
        multi-party-ecdsa/cmp/minimal_key_gen/t_party.cpp
        )

file(GLOB cmp_aux_info_key_refresh_SOURCE
        multi-party-ecdsa/cmp/aux_info_key_refresh/context.cpp
        multi-party-ecdsa/cmp/aux_info_key_refresh/proto_gen/aux_info_key_refresh.pb.switch.cc
        multi-party-ecdsa/cmp/aux_info_key_refresh/round0_bc_message.cpp
        multi-party-ecdsa/cmp/aux_info_key_refresh/round1_bc_message.cpp
        multi-party-ecdsa/cmp/aux_info_key_refresh/round2_p2p_message.cpp
        multi-party-ecdsa/cmp/aux_info_key_refresh/round0.cpp
        multi-party-ecdsa/cmp/aux_info_key_refresh/round1.cpp
        multi-party-ecdsa/cmp/aux_info_key_refresh/round2.cpp
        multi-party-ecdsa/cmp/aux_info_key_refresh/round3.cpp
        multi-party-ecdsa/cmp/aux_info_key_refresh/t_party.cpp
        )

file(GLOB cmp_sign_SOURCE
        multi-party-ecdsa/cmp/sign/auxiliary.cpp
        multi-party-ecdsa/cmp/sign/context.cpp
        multi-party-ecdsa/cmp/sign/round0.cpp
        multi-party-ecdsa/cmp/sign/round1.cpp
        multi-party-ecdsa/cmp/sign/round2.cpp
        multi-party-ecdsa/cmp/sign/round3.cpp
        multi-party-ecdsa/cmp/sign/round4.cpp
        multi-party-ecdsa/cmp/sign/round0_bc_message.cpp
        multi-party-ecdsa/cmp/sign/round0_p2p_message.cpp
        multi-party-ecdsa/cmp/sign/round1_p2p_message.cpp
        multi-party-ecdsa/cmp/sign/round2_p2p_message.cpp
        multi-party-ecdsa/cmp/sign/round3_p2p_message.cpp
        multi-party-ecdsa/cmp/sign/party_local.cpp
        multi-party-ecdsa/cmp/sign/party_remote.cpp
        multi-party-ecdsa/cmp/sign/t_party.cpp
        multi-party-ecdsa/cmp/sign/proto_gen/sign.pb.switch.cc
        )

option(NO_MPC_GG18 "NO_MPC_GG18" OFF)
option(NO_MPC_GG20 "NO_MPC_GG20" OFF)
option(NO_MPC_CMP "NO_MPC_CMP" OFF)

if (NOT ${NO_MPC_GG18})
    MESSAGE(STATUS "NO_MPC_GG18")
    target_sources(${CMAKE_PROJECT_NAME} PRIVATE
            ${gg18_common_SOURCE}
            ${gg18_key_gen_SOURCE}
            ${gg18_key_refresh_SOURCE}
            ${gg18_sign_SOURCE}
            )
endif()

if (NOT ${NO_MPC_GG20})
    target_sources(${CMAKE_PROJECT_NAME} PRIVATE
            ${gg20_sign_SOURCE}
            )
endif()

if (NOT ${NO_MPC_CMP})
    target_sources(${CMAKE_PROJECT_NAME} PRIVATE
            ${cmp_common_SOURCE}
            ${cmp_minimal_key_gen_SOURCE}
            ${cmp_aux_info_key_refresh_SOURCE}
            ${cmp_sign_SOURCE}
            )
endif()


# Refer to single internal library only if it's not assembled into a big library.
option(ENABLE_ASSEMBLE "Enable assemble" OFF)
if (NOT ${ENABLE_ASSEMBLE})
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
endif()