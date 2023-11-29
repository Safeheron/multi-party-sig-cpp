file(GLOB gg18_common_SOURCE
        gg18/proto_gen/struct.pb.switch.cc
        gg18/util.cpp
        gg18/party_local.cpp
        gg18/party_remote.cpp
        gg18/sign_key.cpp
        )

file(GLOB gg18_key_gen_SOURCE
        gg18/key_gen/context.cpp
        gg18/key_gen/proto_gen/key_gen.pb.switch.cc
        gg18/key_gen/round0_bc_message.cpp
        gg18/key_gen/round1_bc_message.cpp
        gg18/key_gen/round1_p2p_message.cpp
        gg18/key_gen/round2_bc_message2.cpp
        gg18/key_gen/round0.cpp
        gg18/key_gen/round1.cpp
        gg18/key_gen/round2.cpp
        gg18/key_gen/round3.cpp
        gg18/key_gen/t_party.cpp
        )

file(GLOB gg18_key_refresh_SOURCE
        gg18/key_refresh/context.cpp
        gg18/key_refresh/proto_gen/key_refresh.pb.switch.cc
        gg18/key_refresh/round0_bc_message.cpp
        gg18/key_refresh/round1_p2p_message.cpp
        gg18/key_refresh/round1_bc_message.cpp
        gg18/key_refresh/round2_p2p_message.cpp
        gg18/key_refresh/round3_bc_message.cpp
        gg18/key_refresh/round0.cpp
        gg18/key_refresh/round1.cpp
        gg18/key_refresh/round2.cpp
        gg18/key_refresh/round3.cpp
        gg18/key_refresh/round4.cpp
        gg18/key_refresh/t_party.cpp
        )

file(GLOB gg18_sign_SOURCE
        gg18/sign/context.cpp
        gg18/sign/round0.cpp
        gg18/sign/round1.cpp
        gg18/sign/round2.cpp
        gg18/sign/round3.cpp
        gg18/sign/round4.cpp
        gg18/sign/round5.cpp
        gg18/sign/round6.cpp
        gg18/sign/round7.cpp
        gg18/sign/round8.cpp
        gg18/sign/round9.cpp
        gg18/sign/round0_bc_message.cpp
        gg18/sign/round0_p2p_message.cpp
        gg18/sign/round1_p2p_message.cpp
        gg18/sign/round2_bc_message.cpp
        gg18/sign/round3_bc_message.cpp
        gg18/sign/round4_bc_message.cpp
        gg18/sign/round5_bc_message.cpp
        gg18/sign/round6_bc_message.cpp
        gg18/sign/round7_bc_message.cpp
        gg18/sign/round8_bc_message.cpp
        multi-party-ecdsa/gg18/sign/party_local.cpp
        multi-party-ecdsa/gg18/sign/party_remote.cpp
        gg18/sign/t_party.cpp
        gg18/sign/mta.cpp
        gg18/sign/proto_gen/sign.pb.switch.cc
        )

file(GLOB gg20_sign_SOURCE
        gg20/sign/context.cpp
        gg20/sign/round0.cpp
        gg20/sign/round1.cpp
        gg20/sign/round2.cpp
        gg20/sign/round3.cpp
        gg20/sign/round4.cpp
        gg20/sign/round5.cpp
        gg20/sign/round6.cpp
        gg20/sign/round7.cpp
        gg20/sign/round0_p2p_message.cpp
        gg20/sign/round0_bc_message.cpp
        gg20/sign/round1_p2p_message.cpp
        gg20/sign/round2_bc_message.cpp
        gg20/sign/round3_bc_message.cpp
        gg20/sign/round4_bc_message.cpp
        gg20/sign/round4_p2p_message.cpp
        gg20/sign/round5_bc_message.cpp
        gg20/sign/round6_bc_message.cpp
        gg20/sign/t_party.cpp
        gg20/sign/proto_gen/sign.pb.switch.cc
        )

file(GLOB cmp_common_SOURCE
        cmp/proto_gen/struct.pb.switch.cc
        cmp/util.cpp
        multi-party-ecdsa/cmp/party_param.cpp
        cmp/party_local.cpp
        cmp/party_remote.cpp
        cmp/sign_key.cpp
        multi-party-ecdsa/cmp/minimal_party_param.cpp
        cmp/minimal_party_local.cpp
        cmp/minimal_party_remote.cpp
        cmp/minimal_sign_key.cpp
        )

file(GLOB cmp_minimal_key_gen_SOURCE
        cmp/minimal_key_gen/context.cpp
        cmp/minimal_key_gen/proto_gen/minimal_key_gen.pb.switch.cc
        cmp/minimal_key_gen/round0_bc_message.cpp
        cmp/minimal_key_gen/round1_p2p_message.cpp
        cmp/minimal_key_gen/round1_bc_message.cpp
        cmp/minimal_key_gen/round2_bc_message.cpp
        cmp/minimal_key_gen/round0.cpp
        cmp/minimal_key_gen/round1.cpp
        cmp/minimal_key_gen/round2.cpp
        cmp/minimal_key_gen/round3.cpp
        cmp/minimal_key_gen/t_party.cpp
        )

file(GLOB cmp_aux_info_key_refresh_SOURCE
        cmp/aux_info_key_refresh/context.cpp
        cmp/aux_info_key_refresh/proto_gen/aux_info_key_refresh.pb.switch.cc
        cmp/aux_info_key_refresh/round0_bc_message.cpp
        cmp/aux_info_key_refresh/round1_bc_message.cpp
        cmp/aux_info_key_refresh/round2_p2p_message.cpp
        cmp/aux_info_key_refresh/round0.cpp
        cmp/aux_info_key_refresh/round1.cpp
        cmp/aux_info_key_refresh/round2.cpp
        cmp/aux_info_key_refresh/round3.cpp
        cmp/aux_info_key_refresh/t_party.cpp
        )

file(GLOB cmp_sign_SOURCE
        multi-party-ecdsa/cmp/sign/auxiliary.cpp
        cmp/sign/context.cpp
        cmp/sign/round0.cpp
        cmp/sign/round1.cpp
        cmp/sign/round2.cpp
        cmp/sign/round3.cpp
        cmp/sign/round4.cpp
        cmp/sign/round0_bc_message.cpp
        cmp/sign/round0_p2p_message.cpp
        cmp/sign/round1_p2p_message.cpp
        cmp/sign/round2_p2p_message.cpp
        cmp/sign/round3_p2p_message.cpp
        multi-party-ecdsa/cmp/sign/party_local.cpp
        multi-party-ecdsa/cmp/sign/party_remote.cpp
        cmp/sign/t_party.cpp
        cmp/sign/proto_gen/sign.pb.switch.cc
        )

file(GLOB cmp_key_recovery_SOURCE
        cmp/key_recovery/context.cpp
        cmp/key_recovery/proto_gen/key_recovery.pb.switch.cc
        cmp/key_recovery/round0_p2p_message.cpp
        cmp/key_recovery/round1_p2p_message.cpp
        cmp/key_recovery/round2_p2p_message.cpp
        cmp/key_recovery/round0.cpp
        cmp/key_recovery/round1.cpp
        cmp/key_recovery/round2.cpp
        cmp/key_recovery/round3.cpp
        )

file(GLOB cmp_key_gen_SOURCE
        cmp/key_gen/context.cpp
        cmp/key_gen/round0.cpp
        cmp/key_gen/round1_6.cpp
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
            ${cmp_key_recovery_SOURCE}
            ${cmp_key_gen_SOURCE}
            )
endif()