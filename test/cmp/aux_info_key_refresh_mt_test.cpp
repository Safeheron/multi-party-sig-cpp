#include <future>
#include <google/protobuf/stubs/common.h>
#include "crypto-suites/exception/located_exception.h"
#include "gtest/gtest.h"
#include "crypto-suites/crypto-curve/curve.h"
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
using safeheron::multi_party_ecdsa::cmp::aux_info_key_refresh::Context;
using safeheron::multi_party_ecdsa::cmp::MinimalSignKey;
using safeheron::multi_party_ecdsa::cmp::SignKey;
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
    EXPECT_TRUE(ctx->sign_key_.ValidityTest());
    string json_str, base64;
    EXPECT_TRUE(ctx->sign_key_.ToJsonString(json_str));
    EXPECT_TRUE(ctx->sign_key_.ToBase64(base64));
    std::string sign_key_info;
    sign_key_info += ctx->sign_key_.local_party_.party_id_ + ": \n";
    sign_key_info += "\"" + base64 + "\"\n";
    sign_key_info += json_str;
    printf("%s\n", sign_key_info.c_str());
}

std::map<std::string, PartyMessageQue<Msg>> map_id_message_queue;

#define ROUNDS 4
#define N_PARTIES 3
#define THRESHOLD 2

bool key_refresh(int n_parties, std::string minimal_sign_key_base64, std::string ssid) {
    bool ok = true;
    std::string status;

    //create context (define in cmp/aux_info_key_refresh/context.h)
    MinimalSignKey minimal_sign_key;
    ok = minimal_sign_key.FromBase64(minimal_sign_key_base64);
    if (!ok) return false;
    Context ctx(n_parties);
    ok = Context::CreateContext(ctx, minimal_sign_key, ssid);
    if (!ok) return false;

    status = "<== Context of " + ctx.sign_key_.local_party_.party_id_ + " was created\n";
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
                ThreadSafeQueue<Msg> &in_queue = map_id_message_queue.at(ctx.sign_key_.local_party_.party_id_).get(round - 1);
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
        status = "<== Round " + std::to_string(round) + ", " + ctx.sign_key_.local_party_.party_id_ + "\n";
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
            Msg m = {ctx.sign_key_.local_party_.party_id_, out_bc_message, out_p2p_message_arr.empty() ? "": out_p2p_message_arr[j]};
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

TEST(cmp, aux_info_key_refresh_mt) {
    std::future<bool> res[N_PARTIES];

    //The common parameters for different curve
    std::string ssid = "ssid";
    std::string party_ids[N_PARTIES] = {
            "co_signer1",
            "co_signer2",
            "co_signer3"
    };

    //SECP256K1 sample
    printf("Test cmp key refresh with secp256k1 curve\n");
    //SECP256k1 sign key
    std::string minimal_sign_key_base64_arr[N_PARTIES] = {
            "EAIYAyLkAQoKY29fc2lnbmVyMRICMDEaQDg5ODBBMjkyRkY0MDEyRThFN0VGRDg1M0I2MEFFNDIzRUY0QjQ4NDA0OUZDMjdCMkI1MjAwQTNENThDMUY4MUIijwEKQDdBMzJDQjhFMDI3RTdENTlGMzhCRTg5NUI3OUZDQTQ0QkVFNTVGNUQxM0ExNkZCREIzRDg3Mjc0QjVFMjlERDYSQEQ4MkVGRDU1ODExMkI0OTdGMUYyM0QxMjMzRkM5MzUwNEQ3QTg2NjlEQjU5RjBCOTFGQzk5MjFEQjFEN0I3MTAaCXNlY3AyNTZrMSqiAQoKY29fc2lnbmVyMhICMDIijwEKQDhFQjAzOThCQTc1QTExODU1OTg2OTVCM0UyQjMwNEVGRkNEQzg4MTZBNjc2MThCMzQ4M0EwNTA1Q0VENzU3ODQSQDk2OURDMjA5Q0IyREIxN0IwQTE0MUQxNTlCM0YwNTJFMkVDNDNGQzU2Qjg4OTZBN0Q0NkU1OEM1QjZCQjczODAaCXNlY3AyNTZrMSqiAQoKY29fc2lnbmVyMxICMDMijwEKQDBEQ0ZBQTUzNjFCNzhFNzREQzFBNjU5NkExNEZEMTUzMzQ3RkE5NEJCREI0NjYzN0MyQzcxODE1QTNCQkM3Q0QSQEJDNDJGQkI3RkI3MTJBOTlEMTk1QTM3MzBDOTY0MjFENTFBNTZCQjRCOENERTcwNkRDODE2MjMwOUI2OUMxMDcaCXNlY3AyNTZrMTKPAQpARDAzQURGRjI3RjBEREZCNDkzRjIyRjJERDg1N0QwM0ZDNENGMEY1NDQ5QzgzRDNDNzk2NEI5NkQ2N0ZCNTQxORJANUE1NzZDQUEyM0QwMkRGRkI4NEZFNkNGMDJENUI1REE0MjVCQTJBMUU1NEU4Q0FBODAxQjVGQzlGRTEzNENCRBoJc2VjcDI1Nmsx",
            "EAIYAyLkAQoKY29fc2lnbmVyMhICMDIaQDUwN0I0RjlCODY1N0JDRjQ4OEFERDQ1MjU0QUVFOUQ5OTdBOTRFNDUwMjY0ODQwMzAwQTE1RTcxRERCQTcxNTgijwEKQDhFQjAzOThCQTc1QTExODU1OTg2OTVCM0UyQjMwNEVGRkNEQzg4MTZBNjc2MThCMzQ4M0EwNTA1Q0VENzU3ODQSQDk2OURDMjA5Q0IyREIxN0IwQTE0MUQxNTlCM0YwNTJFMkVDNDNGQzU2Qjg4OTZBN0Q0NkU1OEM1QjZCQjczODAaCXNlY3AyNTZrMSqiAQoKY29fc2lnbmVyMRICMDEijwEKQDdBMzJDQjhFMDI3RTdENTlGMzhCRTg5NUI3OUZDQTQ0QkVFNTVGNUQxM0ExNkZCREIzRDg3Mjc0QjVFMjlERDYSQEQ4MkVGRDU1ODExMkI0OTdGMUYyM0QxMjMzRkM5MzUwNEQ3QTg2NjlEQjU5RjBCOTFGQzk5MjFEQjFEN0I3MTAaCXNlY3AyNTZrMSqiAQoKY29fc2lnbmVyMxICMDMijwEKQDBEQ0ZBQTUzNjFCNzhFNzREQzFBNjU5NkExNEZEMTUzMzQ3RkE5NEJCREI0NjYzN0MyQzcxODE1QTNCQkM3Q0QSQEJDNDJGQkI3RkI3MTJBOTlEMTk1QTM3MzBDOTY0MjFENTFBNTZCQjRCOENERTcwNkRDODE2MjMwOUI2OUMxMDcaCXNlY3AyNTZrMTKPAQpARDAzQURGRjI3RjBEREZCNDkzRjIyRjJERDg1N0QwM0ZDNENGMEY1NDQ5QzgzRDNDNzk2NEI5NkQ2N0ZCNTQxORJANUE1NzZDQUEyM0QwMkRGRkI4NEZFNkNGMDJENUI1REE0MjVCQTJBMUU1NEU4Q0FBODAxQjVGQzlGRTEzNENCRBoJc2VjcDI1Nmsx",
            "EAIYAyLkAQoKY29fc2lnbmVyMxICMDMaQDE3NzVGQ0E0MEQ2RjY3MDAyOTZCRDA1MEYzNTJFRjhGNDAwNzU0NDlCQUNDRTA1MzRDMjJCMkE2NjJCMkVBOTUijwEKQDBEQ0ZBQTUzNjFCNzhFNzREQzFBNjU5NkExNEZEMTUzMzQ3RkE5NEJCREI0NjYzN0MyQzcxODE1QTNCQkM3Q0QSQEJDNDJGQkI3RkI3MTJBOTlEMTk1QTM3MzBDOTY0MjFENTFBNTZCQjRCOENERTcwNkRDODE2MjMwOUI2OUMxMDcaCXNlY3AyNTZrMSqiAQoKY29fc2lnbmVyMRICMDEijwEKQDdBMzJDQjhFMDI3RTdENTlGMzhCRTg5NUI3OUZDQTQ0QkVFNTVGNUQxM0ExNkZCREIzRDg3Mjc0QjVFMjlERDYSQEQ4MkVGRDU1ODExMkI0OTdGMUYyM0QxMjMzRkM5MzUwNEQ3QTg2NjlEQjU5RjBCOTFGQzk5MjFEQjFEN0I3MTAaCXNlY3AyNTZrMSqiAQoKY29fc2lnbmVyMhICMDIijwEKQDhFQjAzOThCQTc1QTExODU1OTg2OTVCM0UyQjMwNEVGRkNEQzg4MTZBNjc2MThCMzQ4M0EwNTA1Q0VENzU3ODQSQDk2OURDMjA5Q0IyREIxN0IwQTE0MUQxNTlCM0YwNTJFMkVDNDNGQzU2Qjg4OTZBN0Q0NkU1OEM1QjZCQjczODAaCXNlY3AyNTZrMTKPAQpARDAzQURGRjI3RjBEREZCNDkzRjIyRjJERDg1N0QwM0ZDNENGMEY1NDQ5QzgzRDNDNzk2NEI5NkQ2N0ZCNTQxORJANUE1NzZDQUEyM0QwMkRGRkI4NEZFNkNGMDJENUI1REE0MjVCQTJBMUU1NEU4Q0FBODAxQjVGQzlGRTEzNENCRBoJc2VjcDI1Nmsx"
    };
    //Initialize the message queue
    for (int i = 0; i < N_PARTIES; ++i) {
        map_id_message_queue[party_ids[i]] = PartyMessageQue<Msg>(ROUNDS);
    }
    for (int i = 0; i < N_PARTIES; ++i) {
        res[i] = std::async(std::launch::async, key_refresh, N_PARTIES, minimal_sign_key_base64_arr[i], ssid);
    }
    for (int i = 0; i < N_PARTIES; ++i) {
        EXPECT_TRUE(res[i].get());
    }

    //P256 sample
    printf("Test cmp key refresh with p256 curve\n");
    //P256 sign key
    minimal_sign_key_base64_arr[0] = "EAIYAyLfAQoKY29fc2lnbmVyMRICMDEaQDMxOEIxMjI4RjM4OTcyRERDNjZENEY4MUJEMTJGMERCNjcwMzdDQjJCQjFEMTcyMkNCMjQxNEM2NzdFM0RGMzQiigEKQDA1OTlCQzg4QzJBMTFGNkI4QjVBNjVBMzc4QzE5OTc2MzIyMDA5MjQ5MzA5MzMwNDU2RDVFODY2MTYxQjVGREUSQDk4RTRENzE3RDgzOEFGRkFEOUI1Qzg5RTQ4MkI2MDUyNEQ2NzZCNzczRkZFODZCQ0QzMTM5MTI4RTIxNkRDNzYaBHAyNTYqnQEKCmNvX3NpZ25lcjISAjAyIooBCkBCRTBDOUE1NDM1QTg2NzFDQTE1QTUzMzFCNTc4MTRBQjY2NkEyRUE4NUREQUI4RDczOTIxNTg2RDVGNEFBQjI4EkBENkRFQThDQkIyMEM4Mzk4ODhFRDA5NjA4MTRDQzZDQTYyMzk4N0M4MjkyNEM5MkJGMThDMEQyNDAyMTY2RTNFGgRwMjU2Kp0BCgpjb19zaWduZXIzEgIwMyKKAQpAQTQ2OTY0NUM4NkJGREJFOUVENTY1QzNCQzYwRDA5NENCODAwMEQ0RjY0RjUyNjUxNkFDMDIyNEM1MzMxNzhFQxJARERCNTM3MTA1QTlCMTFGRkY4MTcwNDU2QjAyMTY5MzgxREVGRUNCNTc4MkYwQ0NCODc0MjExMEJGN0JENTcxQhoEcDI1NjKKAQpAMjI5MzkwQjQ5QTQxN0IwQTQ2RjNDNjdEQjMzMTg2MUZDRUYyNjNBMzQ2NjAwQTUyODVDMTc5QjcyMTM4RTA0MxJARjY2MjM1MDlBNjIwRUQ3MTNGQ0U2NkQ1NDNCNDY1QjMwQjREQkI1QjM4NkMwRDcwQTI3RjM1NTJEMTMyRDEwNRoEcDI1Ng..";
    minimal_sign_key_base64_arr[1] = "EAIYAyLfAQoKY29fc2lnbmVyMhICMDIaQDgzOUMzQzdGNkU5Qzg0NjhFMzEzRjVDOTNEMTRERjlFNjZCNDAzMzRCQ0I3OERGNDNGQzdFNkUyMUVGNzcwNUMiigEKQEJFMEM5QTU0MzVBODY3MUNBMTVBNTMzMUI1NzgxNEFCNjY2QTJFQTg1RERBQjhENzM5MjE1ODZENUY0QUFCMjgSQEQ2REVBOENCQjIwQzgzOTg4OEVEMDk2MDgxNENDNkNBNjIzOTg3QzgyOTI0QzkyQkYxOEMwRDI0MDIxNjZFM0UaBHAyNTYqnQEKCmNvX3NpZ25lcjESAjAxIooBCkAwNTk5QkM4OEMyQTExRjZCOEI1QTY1QTM3OEMxOTk3NjMyMjAwOTI0OTMwOTMzMDQ1NkQ1RTg2NjE2MUI1RkRFEkA5OEU0RDcxN0Q4MzhBRkZBRDlCNUM4OUU0ODJCNjA1MjRENjc2Qjc3M0ZGRTg2QkNEMzEzOTEyOEUyMTZEQzc2GgRwMjU2Kp0BCgpjb19zaWduZXIzEgIwMyKKAQpAQTQ2OTY0NUM4NkJGREJFOUVENTY1QzNCQzYwRDA5NENCODAwMEQ0RjY0RjUyNjUxNkFDMDIyNEM1MzMxNzhFQxJARERCNTM3MTA1QTlCMTFGRkY4MTcwNDU2QjAyMTY5MzgxREVGRUNCNTc4MkYwQ0NCODc0MjExMEJGN0JENTcxQhoEcDI1NjKKAQpAMjI5MzkwQjQ5QTQxN0IwQTQ2RjNDNjdEQjMzMTg2MUZDRUYyNjNBMzQ2NjAwQTUyODVDMTc5QjcyMTM4RTA0MxJARjY2MjM1MDlBNjIwRUQ3MTNGQ0U2NkQ1NDNCNDY1QjMwQjREQkI1QjM4NkMwRDcwQTI3RjM1NTJEMTMyRDEwNRoEcDI1Ng..";
    minimal_sign_key_base64_arr[2] = "EAIYAyLfAQoKY29fc2lnbmVyMxICMDMaQEQ1QUQ2NkQ1RTlBRjk1RjNGRkJBOUMxMEJEMTZDRTYxNjY2NDg5QjZCRTUyMDRDNUI0NkJCOEZEQzYwQjAxODQiigEKQEE0Njk2NDVDODZCRkRCRTlFRDU2NUMzQkM2MEQwOTRDQjgwMDBENEY2NEY1MjY1MTZBQzAyMjRDNTMzMTc4RUMSQEREQjUzNzEwNUE5QjExRkZGODE3MDQ1NkIwMjE2OTM4MURFRkVDQjU3ODJGMENDQjg3NDIxMTBCRjdCRDU3MUIaBHAyNTYqnQEKCmNvX3NpZ25lcjESAjAxIooBCkAwNTk5QkM4OEMyQTExRjZCOEI1QTY1QTM3OEMxOTk3NjMyMjAwOTI0OTMwOTMzMDQ1NkQ1RTg2NjE2MUI1RkRFEkA5OEU0RDcxN0Q4MzhBRkZBRDlCNUM4OUU0ODJCNjA1MjRENjc2Qjc3M0ZGRTg2QkNEMzEzOTEyOEUyMTZEQzc2GgRwMjU2Kp0BCgpjb19zaWduZXIyEgIwMiKKAQpAQkUwQzlBNTQzNUE4NjcxQ0ExNUE1MzMxQjU3ODE0QUI2NjZBMkVBODVEREFCOEQ3MzkyMTU4NkQ1RjRBQUIyOBJARDZERUE4Q0JCMjBDODM5ODg4RUQwOTYwODE0Q0M2Q0E2MjM5ODdDODI5MjRDOTJCRjE4QzBEMjQwMjE2NkUzRRoEcDI1NjKKAQpAMjI5MzkwQjQ5QTQxN0IwQTQ2RjNDNjdEQjMzMTg2MUZDRUYyNjNBMzQ2NjAwQTUyODVDMTc5QjcyMTM4RTA0MxJARjY2MjM1MDlBNjIwRUQ3MTNGQ0U2NkQ1NDNCNDY1QjMwQjREQkI1QjM4NkMwRDcwQTI3RjM1NTJEMTMyRDEwNRoEcDI1Ng..";
    //Initialize the message queue
    for (int i = 0; i < N_PARTIES; ++i) {
        map_id_message_queue[party_ids[i]] = PartyMessageQue<Msg>(ROUNDS);
    }
    for (int i = 0; i < N_PARTIES; ++i) {
        res[i] = std::async(std::launch::async, key_refresh, N_PARTIES, minimal_sign_key_base64_arr[i], ssid);
    }
    for (int i = 0; i < N_PARTIES; ++i) {
        EXPECT_TRUE(res[i].get());
    }

#ifdef TEST_STARK_CURVE
    //STARK sample
    printf("Test cmp key refresh with stark curve\n");
    //STARK sign key
    minimal_sign_key_base64_arr[0] = "EAIYAyLgAQoKY29fc2lnbmVyMRICMDEaQDAyNDk5MTZDN0U2RkYyMEEzMkE2NjQ2QkVFNDczRkVCMjUwOERGQjU1RUE3MENDNjU4OTNFMzVGOTNDQ0QyQjgiiwEKQDA2M0I4MkIxOEJFRkQzRDc2MkRGOENFQjgwMjE5MDA2NkE0OUFEN0M2QUU3NUUzQUJCREI5NERBODVEQ0FEQjYSQDAzN0Y5RTI0NUQyMjFFMThERDkxQ0FBRTQxREJCNzBBNzkzODQzQzk2MkEzN0NDOEI5M0Y4MDcxODcwRkRGNjgaBXN0YXJrKpwBCgpjb19zaWduZXIyEgIwMiKJAQpAMDZERjNEMEFBMDA3MEI0NjcxMDBGMzEwNEUxQzQ2RTExQjIwRjg4NDBDMTExM0EyQjdGMjVFOTEwNjI3MzM1MhI-RDU3RjRGMTVGOTU5OEFGRkM2NTU0MTRDMENERjY2OTZDQzM2NDZFMDc4MkQyRjAxQzc4NzY5Qzc1RkM5NUUaBXN0YXJrKp4BCgpjb19zaWduZXIzEgIwMyKLAQpAMDMyQ0E2QjU2NkZCMjlFRDdGMTM5NjBFOUIxNEFGRjdGOUE2REZCMEIwMzQ2Q0QwNDI1RDg2RjczOTg1RTlGQRJAMDUxQzIwMzkwODVGQUM3RDgxRTI3RkMzMTY1RTQ5NUM3RjUyQkIxQTU1ODU3MkRBM0Y1QUFFMkE5NTgyRTMxMBoFc3RhcmsyiQEKQDAyQzRDMDMwRjBFNTQ5Q0FENzU5MTVDOUNBODBBNTNFQTc1OTk5RjZGMjgyNTdBMDk0NzcyQUQ2RThENEVDMUYSPjE2NDRDRTNEMTREMkU5RjU2MDc1Nzg2OEVDMDY3MTQyMUI2NUQ5NTMyRkM4NzYwMjhDM0MwMDczNEY5Q0ZBGgVzdGFyaw..";
    minimal_sign_key_base64_arr[1] = "EAIYAyLeAQoKY29fc2lnbmVyMhICMDIaQDA0M0MxOUZBRjNBQUZGNzA4N0ZBQ0RERkQ5ODZCMDVDRDkxQUFEQkM1NzBGODgyQTgyNkM0NjYzQTJGRjJDOTEiiQEKQDA2REYzRDBBQTAwNzBCNDY3MTAwRjMxMDRFMUM0NkUxMUIyMEY4ODQwQzExMTNBMkI3RjI1RTkxMDYyNzMzNTISPkQ1N0Y0RjE1Rjk1OThBRkZDNjU1NDE0QzBDREY2Njk2Q0MzNjQ2RTA3ODJEMkYwMUM3ODc2OUM3NUZDOTVFGgVzdGFyayqeAQoKY29fc2lnbmVyMRICMDEiiwEKQDA2M0I4MkIxOEJFRkQzRDc2MkRGOENFQjgwMjE5MDA2NkE0OUFEN0M2QUU3NUUzQUJCREI5NERBODVEQ0FEQjYSQDAzN0Y5RTI0NUQyMjFFMThERDkxQ0FBRTQxREJCNzBBNzkzODQzQzk2MkEzN0NDOEI5M0Y4MDcxODcwRkRGNjgaBXN0YXJrKp4BCgpjb19zaWduZXIzEgIwMyKLAQpAMDMyQ0E2QjU2NkZCMjlFRDdGMTM5NjBFOUIxNEFGRjdGOUE2REZCMEIwMzQ2Q0QwNDI1RDg2RjczOTg1RTlGQRJAMDUxQzIwMzkwODVGQUM3RDgxRTI3RkMzMTY1RTQ5NUM3RjUyQkIxQTU1ODU3MkRBM0Y1QUFFMkE5NTgyRTMxMBoFc3RhcmsyiQEKQDAyQzRDMDMwRjBFNTQ5Q0FENzU5MTVDOUNBODBBNTNFQTc1OTk5RjZGMjgyNTdBMDk0NzcyQUQ2RThENEVDMUYSPjE2NDRDRTNEMTREMkU5RjU2MDc1Nzg2OEVDMDY3MTQyMUI2NUQ5NTMyRkM4NzYwMjhDM0MwMDczNEY5Q0ZBGgVzdGFyaw..";
    minimal_sign_key_base64_arr[2] = "EAIYAyLgAQoKY29fc2lnbmVyMxICMDMaQDA2MkVBMjg5NjhFNjBDRDZERDRGMzc1M0M0QzYyMENFOEQyQzdCQzM0Rjc4MDM4RUFDNDRBOTY3QjIzMTg2NkEiiwEKQDAzMkNBNkI1NjZGQjI5RUQ3RjEzOTYwRTlCMTRBRkY3RjlBNkRGQjBCMDM0NkNEMDQyNUQ4NkY3Mzk4NUU5RkESQDA1MUMyMDM5MDg1RkFDN0Q4MUUyN0ZDMzE2NUU0OTVDN0Y1MkJCMUE1NTg1NzJEQTNGNUFBRTJBOTU4MkUzMTAaBXN0YXJrKp4BCgpjb19zaWduZXIxEgIwMSKLAQpAMDYzQjgyQjE4QkVGRDNENzYyREY4Q0VCODAyMTkwMDY2QTQ5QUQ3QzZBRTc1RTNBQkJEQjk0REE4NURDQURCNhJAMDM3RjlFMjQ1RDIyMUUxOEREOTFDQUFFNDFEQkI3MEE3OTM4NDNDOTYyQTM3Q0M4QjkzRjgwNzE4NzBGREY2OBoFc3RhcmsqnAEKCmNvX3NpZ25lcjISAjAyIokBCkAwNkRGM0QwQUEwMDcwQjQ2NzEwMEYzMTA0RTFDNDZFMTFCMjBGODg0MEMxMTEzQTJCN0YyNUU5MTA2MjczMzUyEj5ENTdGNEYxNUY5NTk4QUZGQzY1NTQxNEMwQ0RGNjY5NkNDMzY0NkUwNzgyRDJGMDFDNzg3NjlDNzVGQzk1RRoFc3RhcmsyiQEKQDAyQzRDMDMwRjBFNTQ5Q0FENzU5MTVDOUNBODBBNTNFQTc1OTk5RjZGMjgyNTdBMDk0NzcyQUQ2RThENEVDMUYSPjE2NDRDRTNEMTREMkU5RjU2MDc1Nzg2OEVDMDY3MTQyMUI2NUQ5NTMyRkM4NzYwMjhDM0MwMDczNEY5Q0ZBGgVzdGFyaw..";
    //Initialize the message queue
    for (int i = 0; i < N_PARTIES; ++i) {
        map_id_message_queue[party_ids[i]] = PartyMessageQue<Msg>(ROUNDS);
    }
    for (int i = 0; i < N_PARTIES; ++i) {
        res[i] = std::async(std::launch::async, key_refresh, N_PARTIES, minimal_sign_key_base64_arr[i], ssid);
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
