file(GLOB lindell17_key_gen_SOURCE
        lindell17/key_gen/P1Context.cpp
        lindell17/key_gen/P2Context.cpp
        lindell17/key_gen/p1_message1.cpp
        lindell17/key_gen/p1_message2.cpp
        lindell17/key_gen/p1_message3.cpp
        lindell17/key_gen/p1_message4.cpp
        lindell17/key_gen/p2_message1.cpp
        lindell17/key_gen/p2_message2.cpp
        lindell17/key_gen/p2_message3.cpp
        lindell17/key_gen/proto_gen/key_gen.pb.switch.cc
)
file(GLOB lindell17_common_SOURCE
        lindell17/util.cpp
        lindell17/P1KeyShare.cpp
        lindell17/P2KeyShare.cpp
        lindell17/proto_gen/struct.pb.switch.cc
)
file(GLOB lindell17_sign_SOURCE
        lindell17/sign/P1Context.cpp
        lindell17/sign/P2Context.cpp
        lindell17/sign/p1_message0.cpp
        lindell17/sign/p1_message1.cpp
        lindell17/sign/p1_message2.cpp
        lindell17/sign/p2_message0.cpp
        lindell17/sign/p2_message1.cpp
        lindell17/sign/p2_message2.cpp
        lindell17/sign/proto_gen/sign.pb.switch.cc
)

option(NO_LINDELL17 "NO_LINDELL17" OFF)

if (${ENABLE_SNAP_SCOPE})
    set(NO_LINDELL17 TRUE)
endif()

if (NOT ${NO_LINDELL17})
    target_sources(${CMAKE_PROJECT_NAME} PRIVATE
            ${lindell17_key_gen_SOURCE}
            ${lindell17_common_SOURCE}
            ${lindell17_sign_SOURCE}
    )
endif()
