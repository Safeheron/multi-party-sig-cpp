#include "multi-party-sig/multi-party-ecdsa/cmp/key_gen/context.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/util.h"
#include <string>
#include <vector>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/exception/located_exception.h"
#include "../CTimer.h"
#include "../message.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::multi_party_ecdsa::cmp::key_gen::Context;
using safeheron::multi_party_ecdsa::cmp::SignKey;
using safeheron::mpc_flow::mpc_parallel_v2::ErrorInfo;

void print_context_stack_if_failed(Context *ctx_ptr, bool failed){
    if(failed){
        vector<ErrorInfo> error_stack;
        ctx_ptr->get_error_stack(error_stack);
        for(const auto &err: error_stack){
            std::cout << "error code (" << err.code_ << "): " << err.info_ << std::endl;
        }
    }
}

void run_round(Context *ctx_ptr, const std::string& party_id, int round_index,
               std::map<std::string, std::vector<Msg>> &map_id_queue) {
    bool ok = true;

    std::vector<string> out_p2p_message_arr;
    string out_bc_message;
    std::vector<string> out_des_arr;

    if (round_index == 0) {
        ok = ctx_ptr->PushMessage();
        print_context_stack_if_failed(ctx_ptr, !ok);
        ok = ctx_ptr->PopMessages(out_p2p_message_arr, out_bc_message, out_des_arr);
        print_context_stack_if_failed(ctx_ptr, !ok);
        for (size_t k = 0; k < out_des_arr.size(); ++k) {
            map_id_queue[out_des_arr[k]].push_back({
                                                           party_id,
                                                           out_bc_message,
                                                           out_p2p_message_arr.empty() ? string()
                                                                                       : out_p2p_message_arr[k]
                                                   });
        }
    } else {
        std::vector<Msg>::iterator iter;
        for (iter = map_id_queue[party_id].begin(); iter != map_id_queue[party_id].end(); ) {
            ok = ctx_ptr->PushMessage(iter->p2p_msg_, iter->bc_msg_, iter->src_, round_index - 1);
            print_context_stack_if_failed(ctx_ptr, !ok);
            // Check crypto-mpc protocol finished with no error.
            if (ctx_ptr->IsFinished()) {
                std::cout << "<== Finished , Party " << ctx_ptr->minimal_key_gen_ctx_.minimal_sign_key_.local_party_.party_id_ << std::endl;
            }

            iter = map_id_queue[party_id].erase(iter);

            if (ctx_ptr->IsCurRoundFinished()) {
                ok = ctx_ptr->PopMessages(out_p2p_message_arr, out_bc_message, out_des_arr);
                print_context_stack_if_failed(ctx_ptr, !ok);
                for (size_t k = 0; k < out_des_arr.size(); ++k) {
                    map_id_queue[out_des_arr[k]].push_back({
                                                                   party_id,
                                                                   out_bc_message,
                                                                   out_p2p_message_arr.empty() ? string()
                                                                                               : out_p2p_message_arr[k]
                                                           });
                }
                break;
            }
        }
    }
}


void print_sign_key_info(vector<Context*> ctx_arr){
    // print sign_key
    for(size_t i = 0; i < ctx_arr.size(); ++i){
        // Json format of sign_key key
        string json_str;
        EXPECT_TRUE(ctx_arr[i]->sign_key_.ToJsonString(json_str));
        std::cout << ctx_arr[i]->sign_key_.local_party_.party_id_ << ": \n    "
                  << "  - " << ctx_arr[i]->sign_key_.X_.Inspect() << ": \n    "
                  << "  - " << json_str << std::endl;
    }
}

void print_sign_key_bas64_arr(vector<Context*> ctx_arr){
    std::cout << "Aggregated Public Key: " << ctx_arr[0]->sign_key_.X_.Inspect() << std::endl;
    std::cout << "Vault key(base64) of co-signer1, co-signer2 and owner: " << std::endl;
    std::cout << "{ " << std::endl;
    for(size_t i = 0; i < ctx_arr.size(); ++i){
        // Base64 format of sign_key key
        string base64;
        EXPECT_TRUE(ctx_arr[i]->sign_key_.ToBase64(base64));
        if(i != ctx_arr.size() - 1){
            std::cout << "\"" << base64 << "\"," << std::endl;
        } else{
            std::cout << "\"" << base64 << "\"" << std::endl;
        }
        SignKey minimal_sign_key;
        EXPECT_TRUE(minimal_sign_key.FromBase64(base64));
        EXPECT_TRUE(minimal_sign_key.ValidityTest());
    }
    std::cout << "} " << std::endl;
}

void testKeyGen_t_n(CurveType curve_type) {
    string workspace_id("workspace_0");

    std::map<std::string, std::vector<Msg>> map_id_message_queue;

    int threshold = 2;
    int n_parties = 3;

    string party_id_1 = "co_signer1";
    string party_id_2 = "co_signer2";
    string party_id_3 = "co_signer3";

    std::vector<string> party_id_arr = {party_id_1, party_id_2, party_id_3};

    BN party_index_1(1);
    BN party_index_2(2);
    BN party_index_3(3);

    CTimer timer("KeyGen");

    Context party_context_1(3);
    Context party_context_2(3);
    Context party_context_3(3);

    string sid = "sid";

    vector<string> remote_party_id_arr;
    vector<BN> remote_party_index_arr;
    // party 1
    remote_party_id_arr = {party_id_2,
                           party_id_3};
    remote_party_index_arr = {party_index_2,
                              party_index_3};
    Context::CreateContext(party_context_1,
                           curve_type,
                           threshold, n_parties,
                           party_index_1,
                           party_id_1,
                           remote_party_index_arr,
                           remote_party_id_arr,
                           sid
    );
    std::cout << "<== Context of co-signer1 was created" << std::endl;

    // party 2
    remote_party_id_arr = {party_id_1,
                           party_id_3};
    remote_party_index_arr = {party_index_1,
                              party_index_3};
    Context::CreateContext(party_context_2,
                           curve_type,
                           threshold, n_parties,
                           party_index_2,
                           party_id_2,
                           remote_party_index_arr,
                           remote_party_id_arr,
                           sid
    );
    std::cout << "<== Context of co-signer2 was created" << std::endl;

    // party 3
    remote_party_id_arr = {party_id_1,
                           party_id_2};
    remote_party_index_arr = {party_index_1,
                              party_index_2};
    BN N, s, t, p, q, alpha, beta;
    safeheron::multi_party_ecdsa::cmp::prepare_data(N, s, t, p, q, alpha, beta);
    Context::CreateContext(party_context_3,
                           curve_type,
                           threshold, n_parties,
                           party_index_3,
                           party_id_3,
                           remote_party_index_arr,
                           remote_party_id_arr,
                           sid,N,s,t,p,q,alpha,
                           beta
    );
    std::cout << "<== Context of co-signer3 was created" << std::endl;

    vector<Context *> ctx_arr = {&party_context_1, &party_context_2, &party_context_3};

    // round 0 ~ 3
    for (int round = 0; round <= 6; ++round) {
        // context 0 ~ 2 (co-signer1, co-signer2, co-signer3)
        for (int i = 0; i < 3; ++i) {
            std::cout << "<== Round " << round << ", " << ctx_arr[i]->minimal_key_gen_ctx_.minimal_sign_key_.local_party_.party_id_  << std::endl;
            run_round(ctx_arr[i], party_id_arr[i], round, map_id_message_queue);
        }
    }

    // print sign_key
    for (int i = 0; i < 3; ++i) {
        // Json format of sign_key key
        string json_str;
        EXPECT_TRUE(ctx_arr[i]->sign_key_.ToJsonString(json_str));
        std::cout << ctx_arr[i]->sign_key_.local_party_.party_id_ << ": \n    "
                  << "  - " << json_str << std::endl;
        // Base64 format of sign_key key
        string base64;
        EXPECT_TRUE(ctx_arr[i]->sign_key_.ToBase64(base64));
        // std::cout << ctx_arr[i]->sign_key_.local_party_.party_id_ << ": \n    "
        //           << "  - " << base64<< std::endl;
        SignKey sign_key;
        EXPECT_TRUE(sign_key.FromBase64(base64));
        EXPECT_TRUE(sign_key.ValidityTest());
    }

    timer.End();

    print_sign_key_info(ctx_arr);

    std::cout << "Vault key(base64) of co-signer1, co-signer2 and co-signer3: " << std::endl;
    print_sign_key_bas64_arr(ctx_arr);
}

TEST(KeyGen, KeyGen_t_n)
{
    // while t < n
    try {
        std::cout << "Test cmp key generation with SECP256K1 curve:" << std::endl;
        testKeyGen_t_n(safeheron::curve::CurveType::SECP256K1);

        std::cout << "Test cmp key generation with P256 curve:" << std::endl;
        testKeyGen_t_n(safeheron::curve::CurveType::P256);

#ifdef TEST_STARK_CURVE
        std::cout << "Test cmp key generation with STARK curve:" << std::endl;
        testKeyGen_t_n(safeheron::curve::CurveType::STARK);
#endif

    } catch (const safeheron::exception::LocatedException &e) {
        std::cout << "Exception: " << e.what() << std::endl;
    }
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
