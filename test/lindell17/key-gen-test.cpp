#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "multi-party-sig/two-party-ecdsa/lindell17/P1KeyShare.h"
#include "multi-party-sig/two-party-ecdsa/lindell17/P2KeyShare.h"
#include "multi-party-sig/two-party-ecdsa/lindell17/key_gen/message.h"
#include "multi-party-sig/two-party-ecdsa/lindell17/key_gen/P1Context.h"
#include "multi-party-sig/two-party-ecdsa/lindell17/key_gen/P2Context.h"

using safeheron::two_party_ecdsa::lindell17::key_gen::P1Context;
using safeheron::two_party_ecdsa::lindell17::key_gen::P2Context;

using safeheron::two_party_ecdsa::lindell17::key_gen::P1Message1;
using safeheron::two_party_ecdsa::lindell17::key_gen::P1Message2;
using safeheron::two_party_ecdsa::lindell17::key_gen::P1Message3;

using safeheron::two_party_ecdsa::lindell17::key_gen::P2Message1;
using safeheron::two_party_ecdsa::lindell17::key_gen::P2Message2;

using safeheron::two_party_ecdsa::lindell17::P1KeyShare;
using safeheron::two_party_ecdsa::lindell17::P2KeyShare;

TEST(lindell17, key_gen) {
    P1Context p1_context;
    P2Context p2_context;
    p1_context.CreateContext(safeheron::curve::CurveType::SECP256K1);
    p2_context.CreateContext(safeheron::curve::CurveType::SECP256K1);

    bool ok = true;
    std::string p1_message1;
    ok = p1_context.Step1(p1_message1);
    EXPECT_TRUE(ok);
    std::string p2_message1;
    ok = p2_context.Step1(p1_message1, p2_message1);
    EXPECT_TRUE(ok);

    std::string p1_message2;
    ok = p1_context.Step2(p2_message1, p1_message2);
    EXPECT_TRUE(ok);
    std::string p2_message2;
    ok = p2_context.Step2(p1_message2, p2_message2);
    EXPECT_TRUE(ok);

    std::string p1_message3;
    ok = p1_context.Step3(p2_message2, p1_message3);
    EXPECT_TRUE(ok);
    std::string p2_message3;
    ok = p2_context.Step3(p1_message3, p2_message3);
    EXPECT_TRUE(ok);

    std::string p1_message4;
    ok = p1_context.Step4(p2_message3, p1_message4);
    EXPECT_TRUE(ok);
    ok = p2_context.Step4(p1_message4);
    EXPECT_TRUE(ok);

    std::string key_share_1_b64;
    std::string key_share_2_b64;
    ok = p1_context.export_key_share(key_share_1_b64);
    EXPECT_TRUE(ok);
    ok = p2_context.export_key_share(key_share_2_b64);
    EXPECT_TRUE(ok);

    std::cout << "key_share_1_b64:\n" << key_share_1_b64 << std::endl;
    std::cout << "key_share_2_b64:\n" << key_share_2_b64 << std::endl;

    P1KeyShare key_share_1;
    ok = key_share_1.FromBase64(key_share_1_b64);
    EXPECT_TRUE(ok);
    P2KeyShare key_share_2;
    ok = key_share_2.FromBase64(key_share_2_b64);
    EXPECT_TRUE(ok);

    std::string key_share_1_json_str;
    key_share_1.ToJsonString(key_share_1_json_str);
    std::string key_share_2_json_str;
    key_share_2.ToJsonString(key_share_2_json_str);

    std::cout << "key_share_1:\n" << key_share_1_json_str << std::endl;
    std::cout << "key_share_2:\n" << key_share_2_json_str << std::endl;
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}