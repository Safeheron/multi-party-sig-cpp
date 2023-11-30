#include <future>
#include <vector>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/exception/located_exception.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/cmp.h"
#include "../thread_safe_queue.h"
#include "../message.h"
#include "../party_message_queue.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::multi_party_ecdsa::cmp::minimal_key_gen::Context;
using safeheron::multi_party_ecdsa::cmp::MinimalSignKey;
using safeheron::mpc_flow::mpc_parallel_v2::ErrorInfo;

void print_context_stack_if_failed(Context *ctx) {
    std::string err_info;
    vector<ErrorInfo> error_stack;
    ctx->get_error_stack(error_stack);
    for(const auto &err: error_stack){
        err_info += "error code ( " + std::to_string(err.code_) + " ) : " + err.info_ + "\n";
    }
    printf("%s", err_info.c_str());
}
void print_sign_key_info(Context *ctx) {
    EXPECT_TRUE(ctx->minimal_sign_key_.ValidityTest());
    string json_str, base64;
    EXPECT_TRUE(ctx->minimal_sign_key_.ToJsonString(json_str));
    EXPECT_TRUE(ctx->minimal_sign_key_.ToBase64(base64));
    std::string sign_key_info;
    sign_key_info += ctx->minimal_sign_key_.local_party_.party_id_ + ": \n";
    sign_key_info += "\"" + base64 + "\"\n";
    sign_key_info += json_str;
    printf("%s\n", sign_key_info.c_str());
}

std::map<std::string, PartyMessageQue<Msg>> map_id_message_queue;

#define ROUNDS 4
#define N_PARTIES 3
#define THRESHOLD 2

bool key_gen(CurveType curve_type, int n_parties, int threshold, std::string party_id, BN index, std::vector<std::string> remote_party_ids, std::vector<BN> remote_party_indexes, std::string ssid) {
    bool ok = true;
    std::string status;

    //create context (define in cmp/minimal_key_gen/context.h)
    const Curve * curv = safeheron::curve::GetCurveParam(curve_type);
    BN sk = safeheron::rand::RandomBNLt(curv->n);
    Context ctx(n_parties);
    ok = Context::CreateContext(ctx, curve_type, threshold, n_parties, sk, index, party_id, remote_party_indexes, remote_party_ids, ssid);
    if (!ok) return false;

    status = "<== Context of " + party_id + " was created\n";
    printf("%s", status.c_str());

    //perform 3 rounds of MPC
    for (int round = 0; round < ROUNDS; ++round) {
        if (round == 0) {
            ok = ctx.PushMessage();
            if (!ok) {
                print_context_stack_if_failed(&ctx);
                return false;
            }
        } else {
            for(int k = 0; k < n_parties - 1; k++) {
                Msg m;
                ThreadSafeQueue<Msg> &in_queue = map_id_message_queue.at(ctx.minimal_sign_key_.local_party_.party_id_).get(round - 1);
                in_queue.Pop(m);
                ok = ctx.PushMessage(m.p2p_msg_, m.bc_msg_, m.src_, round - 1);
                if (!ok) {
                    print_context_stack_if_failed(&ctx);
                    return false;
                }
            }
        }

        ok = ctx.IsCurRoundFinished();
        if (!ok) {
            print_context_stack_if_failed(&ctx);
            return false;
        }
        status = "<== Round " + std::to_string(round) + ", " + party_id + " \n";
        printf("%s", status.c_str());

        std::string out_bc_message;
        vector<string> out_p2p_message_arr;
        vector<string> out_des_arr;
        ok = ctx.PopMessages(out_p2p_message_arr, out_bc_message, out_des_arr);
        if (!ok) {
            print_context_stack_if_failed(&ctx);
            return false;
        }

        for (size_t j = 0; j < out_des_arr.size(); ++j) {
            Msg m = {ctx.minimal_sign_key_.local_party_.party_id_, out_bc_message, out_p2p_message_arr.empty() ? "": out_p2p_message_arr[j]};
            ThreadSafeQueue<Msg> &out_queue = map_id_message_queue.at(out_des_arr[j]).get(round);
            out_queue.Push(m);
        }
    }

    ok = ctx.IsFinished();
    if (!ok) {
        print_context_stack_if_failed(&ctx);
        return false;
    }

    print_sign_key_info(&ctx);
    return true;
}

TEST(cmp, minimal_key_gen_mt) {
    std::future<bool> res[N_PARTIES];

    //The common parameters for different curves
    string ssid = "ssid";
    std::string party_ids[N_PARTIES] = {
            "co_signer1",
            "co_signer2",
            "co_signer3"
    };
    BN indexes[N_PARTIES] = {
            BN(1),
            BN(2),
            BN(3)
    };

    //SECP256K1 sample
    printf("Test cmp key generation with secp256k1 curve\n");
    //Initialize the message queue
    for (int i = 0; i < N_PARTIES; ++i) {
        map_id_message_queue[party_ids[i]] = PartyMessageQue<Msg>(ROUNDS);
    }
    for (int i = 0; i < N_PARTIES; ++i) {
        std::vector<std::string> remote_party_ids;
        std::vector<BN> remote_party_indexes;
        for (int j = 0; j < N_PARTIES; ++j) {
            if (j != i) {
                remote_party_ids.push_back(party_ids[j]);
                remote_party_indexes.push_back(indexes[j]);
            }
        }
        res[i] = std::async(std::launch::async, key_gen, CurveType::SECP256K1, N_PARTIES, THRESHOLD, party_ids[i], indexes[i], remote_party_ids, remote_party_indexes, ssid);
    }
    for (int i = 0; i < N_PARTIES; ++i) {
        EXPECT_TRUE(res[i].get());
    }

    //P256 sample
    printf("Test cmp key generation with p256 curve\n");
    //Initialize the message queue
    for (int i = 0; i < N_PARTIES; ++i) {
        map_id_message_queue[party_ids[i]] = PartyMessageQue<Msg>(ROUNDS);
    }
    for (int i = 0; i < N_PARTIES; ++i) {
        std::vector<std::string> remote_party_ids;
        std::vector<BN> remote_party_indexes;
        for (int j = 0; j < N_PARTIES; ++j) {
            if (j != i) {
                remote_party_ids.push_back(party_ids[j]);
                remote_party_indexes.push_back(indexes[j]);
            }
        }
        res[i] = std::async(std::launch::async, key_gen, CurveType::P256, N_PARTIES, THRESHOLD, party_ids[i], indexes[i], remote_party_ids, remote_party_indexes, ssid);
    }
    for (int i = 0; i < N_PARTIES; ++i) {
        EXPECT_TRUE(res[i].get());
    }

#ifdef TEST_STARK_CURVE
    //STARK sample
    printf("Test cmp key generation with stark curve\n");
    //Initialize the message queue
    for (int i = 0; i < N_PARTIES; ++i) {
        map_id_message_queue[party_ids[i]] = PartyMessageQue<Msg>(ROUNDS);
    }
    for (int i = 0; i < N_PARTIES; ++i) {
        std::vector<std::string> remote_party_ids;
        std::vector<BN> remote_party_indexes;
        for (int j = 0; j < N_PARTIES; ++j) {
            if (j != i) {
                remote_party_ids.push_back(party_ids[j]);
                remote_party_indexes.push_back(indexes[j]);
            }
        }
        res[i] = std::async(std::launch::async, key_gen, CurveType::STARK, N_PARTIES, THRESHOLD, party_ids[i], indexes[i], remote_party_ids, remote_party_indexes, ssid);
    }
    for (int i = 0; i < N_PARTIES; ++i) {
        EXPECT_TRUE(res[i].get());
    }
#endif

}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}



