
#include <cstring>
#include <vector>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/exception/located_exception.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/cmp.h"
#include "../CTimer.h"
#include "../message.h"

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
                std::cout << "<== Finished , Party " << ctx_ptr->sign_key_.local_party_.party_id_ << std::endl;
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
    std::cout << "Vault key(base64) of co-signer1, co-signer2 and co_signer3: " << std::endl;
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
        MinimalSignKey minimal_sign_key;
        EXPECT_TRUE(minimal_sign_key.FromBase64(base64));
        EXPECT_TRUE(minimal_sign_key.ValidityTest());
    }
    std::cout << "} " << std::endl;
}

void testKeyRefresh(std::vector<std::string> &minimal_sign_key_base64){
    // t == n == 3
    bool ok = true;
    const Curve * curv = safeheron::curve::GetCurveParam(safeheron::curve::CurveType::SECP256K1);

    std::map<std::string, std::vector<Msg>> map_id_message_queue;

    string workspace_id("workspace_0");
    int threshold = 3;
    int n_parties = 3;

    Context co_signer1_context(3);
    Context co_signer2_context(3);
    Context co_signer3_context(3);

    MinimalSignKey minimal_sign_key_1;
    MinimalSignKey minimal_sign_key_2;
    MinimalSignKey minimal_sign_key_3;
    ok = minimal_sign_key_1.FromBase64(minimal_sign_key_base64[0]);
    if(!ok){
        std::cout << "failed to parse nake_sign_key 1" << std::endl;
    }
    ok = minimal_sign_key_2.FromBase64(minimal_sign_key_base64[1]);
    if(!ok){
        std::cout << "failed to parse nake_sign_key 2" << std::endl;
    }
    ok = minimal_sign_key_3.FromBase64(minimal_sign_key_base64[2]);
    if(!ok){
        std::cout << "failed to parse nake_sign_key 3" << std::endl;
    }

    string ssid = "ssid";

    // co-signer1
    Context::CreateContext(co_signer1_context, minimal_sign_key_1, ssid);
    std::cout << "<== Context of co-signer1 was created" << std:: endl;

    // co-signer2
    Context::CreateContext(co_signer2_context, minimal_sign_key_2, ssid);
    std::cout << "<== Context of co-signer2 was created" << std:: endl;

    // co-signer3
    Context::CreateContext(co_signer3_context, minimal_sign_key_3, ssid);
    std::cout << "<== Context of co-signer3 was created" << std:: endl;

    vector<Context* > ctx_arr = {&co_signer1_context, &co_signer2_context, &co_signer3_context};

    // round 0 ~ 3
    for (int round = 0; round <= 3; ++round) {
        // context 0 ~ 2 (co-signer1, co-signer2, co-signer3)
        for (int i = 0; i < 3; ++i) {
            std::cout << "<== Round " << round << ", " << ctx_arr[i]->sign_key_.local_party_.party_id_  << std::endl;
            run_round(ctx_arr[i], ctx_arr[i]->sign_key_.local_party_.party_id_, round, map_id_message_queue);
        }
    }

    // print sign_key
    for(int i = 0; i < 3; ++i){
        // Json format of sign_key key
        string json_str;
        EXPECT_TRUE(ctx_arr[i]->sign_key_.ToJsonString(json_str));
        std::cout << ctx_arr[i]->sign_key_.local_party_.party_id_ << ": \n    "
                  << "  - " << ctx_arr[i]->sign_key_.X_.Inspect() << ": \n    "
                  << "  - " << json_str << std::endl;
        // Base64 format of sign_key key
        string base64;
        EXPECT_TRUE(ctx_arr[i]->sign_key_.ToBase64(base64));
        // std::cout << ctx_arr[i]->sign_key_.local_party_.party_id_ << ": \n    "
        //           << "  - " << base64<< std::endl;
        MinimalSignKey sign_key;
        EXPECT_TRUE(sign_key.FromBase64(base64));
        EXPECT_TRUE(sign_key.ValidityTest());
    }


    std::cout << "Vault key(base64) of co-signer1, co-signer2 and co_signer3: " << std::endl;
    print_sign_key_bas64_arr(ctx_arr);
}

TEST(CoSignKey, KeyRefresh)
{
    std::cout << "Test cmp key refresh with SECP256K1 curve" << std::endl;
    //SECP256k1 sign key
    vector<string> minimal_sign_key_base64_arr_1 = {
            "EAMYAyLkAQoKY29fc2lnbmVyMRICMDEaQDI0ODlEMEU2QjY3RkVGNjVFN0U0NUZEQjI0Q0E5ODRFOURGQkMxNzMxREYwNzgzNjY4OTFDMjEwMEQ2N0I5OTUijwEKQDEwNzJEQjIzOTE5RDY1QjU3NERCOEQ5NjlEN0E2RUZDRjdENDRERTUxQTNDQkE2MzEwMDQxQjRBMTI3OUM2RDUSQEVGREEzRDEzMThFNUMyRUEyMjFCRDA3NDUwOUM1RjEyOUVCRUM4NEFDODBEREY1NEM2QzNGOUExRTA3Njc3MzcaCXNlY3AyNTZrMSqiAQoKY29fc2lnbmVyMhICMDIijwEKQDExRDc2MUREREI1NDBDMjRCOEJFNjA1RjNFRTE1QTdGNzc2RkYxQTNDODY1NUVCMzg1QzhDRTA2QkE3QjNCMTESQDI2QzMwN0U4NjU0QTFDQkU1QTcxRjhENERGNkUxRDNDQjdBQ0Y4NTFGOUJDRDQ1MEMyQTY1NTc3NjY1NjEzNDgaCXNlY3AyNTZrMSqiAQoKY29fc2lnbmVyMxICMDMijwEKQDRFNTE5MkE1QjI4RUMzMjcxQjcxQzEzMEM3MTRBM0NDQjk4NTU2ODk4REJCQjk1NTRCRDhEQ0M2N0QyQTdBQzQSQDY2RjBEREMxNEMyRkY4MTE2Mzk0Q0NERkFDM0MyNkExODM0RjFGRDcyQzUxN0Q5MkNERDUxQUU4OUQ5NjE5OTAaCXNlY3AyNTZrMTKPAQpAMUVERjNCRkRGMUMzN0Y1N0NENTI2RjJENDdGNzkwMkIzRTY1MDlFRkJDNzkxRTc3NTQ2QzhEQThFNzdCRjRENxJANUIxMDhGNzlDOTgyRDcwRDkwRjgxMUFGMDJENzAzRjNFRTM4OUY4M0M0MzVEOTVCMDA4MzIyN0IxQjg3Q0YyNxoJc2VjcDI1Nmsx",
            "EAMYAyLkAQoKY29fc2lnbmVyMhICMDIaQEU3MjY3RTU0MkQ0NjY4ODdEM0M4RUZGMjdCQjUzODExOUM2MENCQ0IzRDZDRUY5RjBGQ0RFOEZBQzM1RTU5NjIijwEKQDExRDc2MUREREI1NDBDMjRCOEJFNjA1RjNFRTE1QTdGNzc2RkYxQTNDODY1NUVCMzg1QzhDRTA2QkE3QjNCMTESQDI2QzMwN0U4NjU0QTFDQkU1QTcxRjhENERGNkUxRDNDQjdBQ0Y4NTFGOUJDRDQ1MEMyQTY1NTc3NjY1NjEzNDgaCXNlY3AyNTZrMSqiAQoKY29fc2lnbmVyMRICMDEijwEKQDEwNzJEQjIzOTE5RDY1QjU3NERCOEQ5NjlEN0E2RUZDRjdENDRERTUxQTNDQkE2MzEwMDQxQjRBMTI3OUM2RDUSQEVGREEzRDEzMThFNUMyRUEyMjFCRDA3NDUwOUM1RjEyOUVCRUM4NEFDODBEREY1NEM2QzNGOUExRTA3Njc3MzcaCXNlY3AyNTZrMSqiAQoKY29fc2lnbmVyMxICMDMijwEKQDRFNTE5MkE1QjI4RUMzMjcxQjcxQzEzMEM3MTRBM0NDQjk4NTU2ODk4REJCQjk1NTRCRDhEQ0M2N0QyQTdBQzQSQDY2RjBEREMxNEMyRkY4MTE2Mzk0Q0NERkFDM0MyNkExODM0RjFGRDcyQzUxN0Q5MkNERDUxQUU4OUQ5NjE5OTAaCXNlY3AyNTZrMTKPAQpAMUVERjNCRkRGMUMzN0Y1N0NENTI2RjJENDdGNzkwMkIzRTY1MDlFRkJDNzkxRTc3NTQ2QzhEQThFNzdCRjRENxJANUIxMDhGNzlDOTgyRDcwRDkwRjgxMUFGMDJENzAzRjNFRTM4OUY4M0M0MzVEOTVCMDA4MzIyN0IxQjg3Q0YyNxoJc2VjcDI1Nmsx",
            "EAMYAyLkAQoKY29fc2lnbmVyMxICMDMaQEY3NjhEODAwMDFENTY0MTk1RjM1Q0IxQkExODZBQ0E4MTM2NDUzMzQ0QzQ1RTdBNEU2MDkxRERBQTM5OTkwRjIijwEKQDRFNTE5MkE1QjI4RUMzMjcxQjcxQzEzMEM3MTRBM0NDQjk4NTU2ODk4REJCQjk1NTRCRDhEQ0M2N0QyQTdBQzQSQDY2RjBEREMxNEMyRkY4MTE2Mzk0Q0NERkFDM0MyNkExODM0RjFGRDcyQzUxN0Q5MkNERDUxQUU4OUQ5NjE5OTAaCXNlY3AyNTZrMSqiAQoKY29fc2lnbmVyMRICMDEijwEKQDEwNzJEQjIzOTE5RDY1QjU3NERCOEQ5NjlEN0E2RUZDRjdENDRERTUxQTNDQkE2MzEwMDQxQjRBMTI3OUM2RDUSQEVGREEzRDEzMThFNUMyRUEyMjFCRDA3NDUwOUM1RjEyOUVCRUM4NEFDODBEREY1NEM2QzNGOUExRTA3Njc3MzcaCXNlY3AyNTZrMSqiAQoKY29fc2lnbmVyMhICMDIijwEKQDExRDc2MUREREI1NDBDMjRCOEJFNjA1RjNFRTE1QTdGNzc2RkYxQTNDODY1NUVCMzg1QzhDRTA2QkE3QjNCMTESQDI2QzMwN0U4NjU0QTFDQkU1QTcxRjhENERGNkUxRDNDQjdBQ0Y4NTFGOUJDRDQ1MEMyQTY1NTc3NjY1NjEzNDgaCXNlY3AyNTZrMTKPAQpAMUVERjNCRkRGMUMzN0Y1N0NENTI2RjJENDdGNzkwMkIzRTY1MDlFRkJDNzkxRTc3NTQ2QzhEQThFNzdCRjRENxJANUIxMDhGNzlDOTgyRDcwRDkwRjgxMUFGMDJENzAzRjNFRTM4OUY4M0M0MzVEOTVCMDA4MzIyN0IxQjg3Q0YyNxoJc2VjcDI1Nmsx"
    };
    testKeyRefresh(minimal_sign_key_base64_arr_1);

    std::cout << "Test cmp key refresh with P256 curve" << std::endl;
    //P256 sign key
    vector<string> minimal_sign_key_base64_arr_2 = {
            "EAMYAyLfAQoKY29fc2lnbmVyMRICMDEaQDA1MENCRDlENUUyNkFCNTkzQUEwRDI3RDM4NEM0MDMzMEI2QzJFMTU0NzhCOEQwNjIxRERERUE4NTNBRkMyMkEiigEKQDg0RjM2M0RGRDg5RTQ0MDczMTcyN0Y4NzM3QzA1OEYzQTE5QTZERDNGNjlENDA1RDU2QjFGN0Y2MERDMDNEQzQSQDZCQzRDRTUzQ0JGMzQzQzA2QkMwMjFFQUU1MEJFRUM4NEI5MDIxNzc0MUM5NTA5RDZDNzA1RkE2ODBBRkNGNDcaBHAyNTYqnQEKCmNvX3NpZ25lcjISAjAyIooBCkAxRUNDRTg3MjhGRjYzMzQyQTNFMDI5MDY5MUEzNTM2MDQ0RkZBNDNBOTFDRERCQjhBRUVGOURGMDg3MzlENkI1EkA5QjJEODUzOEFCNEQxNjBCRTQ1M0I4QjBGQ0VFODZBRTBDQzkxOTk5QkI2MjY0MUUwNzIwQTQyMEMxMTIyRjg5GgRwMjU2Kp0BCgpjb19zaWduZXIzEgIwMyKKAQpANzg0OTY0MEZCQjdGODlFNDNCMjBENzAzNDI4RjQyMkEyNjAyNTYzODZBQUU2OUNBMjc0NDNDNTdBQTUxNUUyRhJANkM0NDg1OEI1QzVCRDhDMzcwNjY4QjA3RTg0NURCMTZDNEJCOEJEQjUyQTI5QTJBODYzQTI2QkNEQzYzQzc4NxoEcDI1NjKKAQpAQzg4OUVFRDBCMkQzQjdGQTU0MjBBMjUyRTk1RThCNjYyQTgzRjAyQ0JENTQwMDMzRTdBRjI0QUE5NUQxOUY3MhJAQjk3MTIxNzIxNDQzMTg1QTUyNEY1RDFGNTk5RUY5MUQ0QzQxQTRFN0RDMzFBMjc5QzI1QjRBOEJGODU5MTc0NRoEcDI1Ng..",
            "EAMYAyLfAQoKY29fc2lnbmVyMhICMDIaQDg1NjRCODk0NERCOUFBMDY3OUYyQjRBNzY4RkFDMUY3OUM4MUNCMzU3NTE4RTM0Nzk0NUYyNTgzRUIxMzBDQzciigEKQDFFQ0NFODcyOEZGNjMzNDJBM0UwMjkwNjkxQTM1MzYwNDRGRkE0M0E5MUNEREJCOEFFRUY5REYwODczOUQ2QjUSQDlCMkQ4NTM4QUI0RDE2MEJFNDUzQjhCMEZDRUU4NkFFMENDOTE5OTlCQjYyNjQxRTA3MjBBNDIwQzExMjJGODkaBHAyNTYqnQEKCmNvX3NpZ25lcjESAjAxIooBCkA4NEYzNjNERkQ4OUU0NDA3MzE3MjdGODczN0MwNThGM0ExOUE2REQzRjY5RDQwNUQ1NkIxRjdGNjBEQzAzREM0EkA2QkM0Q0U1M0NCRjM0M0MwNkJDMDIxRUFFNTBCRUVDODRCOTAyMTc3NDFDOTUwOUQ2QzcwNUZBNjgwQUZDRjQ3GgRwMjU2Kp0BCgpjb19zaWduZXIzEgIwMyKKAQpANzg0OTY0MEZCQjdGODlFNDNCMjBENzAzNDI4RjQyMkEyNjAyNTYzODZBQUU2OUNBMjc0NDNDNTdBQTUxNUUyRhJANkM0NDg1OEI1QzVCRDhDMzcwNjY4QjA3RTg0NURCMTZDNEJCOEJEQjUyQTI5QTJBODYzQTI2QkNEQzYzQzc4NxoEcDI1NjKKAQpAQzg4OUVFRDBCMkQzQjdGQTU0MjBBMjUyRTk1RThCNjYyQTgzRjAyQ0JENTQwMDMzRTdBRjI0QUE5NUQxOUY3MhJAQjk3MTIxNzIxNDQzMTg1QTUyNEY1RDFGNTk5RUY5MUQ0QzQxQTRFN0RDMzFBMjc5QzI1QjRBOEJGODU5MTc0NRoEcDI1Ng..",
            "EAMYAyLfAQoKY29fc2lnbmVyMxICMDMaQEIzMjFGODA1QzI4NDkwRTA3REIwQTdEQUVERjQxQjRFQTBCMTkxMEM4NEJBMDY1RDdCNEI1OEVFMTI2RTQ5MDUiigEKQDc4NDk2NDBGQkI3Rjg5RTQzQjIwRDcwMzQyOEY0MjJBMjYwMjU2Mzg2QUFFNjlDQTI3NDQzQzU3QUE1MTVFMkYSQDZDNDQ4NThCNUM1QkQ4QzM3MDY2OEIwN0U4NDVEQjE2QzRCQjhCREI1MkEyOUEyQTg2M0EyNkJDREM2M0M3ODcaBHAyNTYqnQEKCmNvX3NpZ25lcjESAjAxIooBCkA4NEYzNjNERkQ4OUU0NDA3MzE3MjdGODczN0MwNThGM0ExOUE2REQzRjY5RDQwNUQ1NkIxRjdGNjBEQzAzREM0EkA2QkM0Q0U1M0NCRjM0M0MwNkJDMDIxRUFFNTBCRUVDODRCOTAyMTc3NDFDOTUwOUQ2QzcwNUZBNjgwQUZDRjQ3GgRwMjU2Kp0BCgpjb19zaWduZXIyEgIwMiKKAQpAMUVDQ0U4NzI4RkY2MzM0MkEzRTAyOTA2OTFBMzUzNjA0NEZGQTQzQTkxQ0REQkI4QUVFRjlERjA4NzM5RDZCNRJAOUIyRDg1MzhBQjREMTYwQkU0NTNCOEIwRkNFRTg2QUUwQ0M5MTk5OUJCNjI2NDFFMDcyMEE0MjBDMTEyMkY4ORoEcDI1NjKKAQpAQzg4OUVFRDBCMkQzQjdGQTU0MjBBMjUyRTk1RThCNjYyQTgzRjAyQ0JENTQwMDMzRTdBRjI0QUE5NUQxOUY3MhJAQjk3MTIxNzIxNDQzMTg1QTUyNEY1RDFGNTk5RUY5MUQ0QzQxQTRFN0RDMzFBMjc5QzI1QjRBOEJGODU5MTc0NRoEcDI1Ng.."
    };
    testKeyRefresh(minimal_sign_key_base64_arr_2);

#ifdef TEST_STARK_CURVE
    std::cout << "Test cmp key refresh with STARK curve" << std::endl;
    //STARK sign key
    vector<string> minimal_sign_key_base64_arr_3 = {
                "EAMYAyLgAQoKY29fc2lnbmVyMRICMDEaQDA1RDk2OUE1ODM4NTA2MTdFN0FDNTVBRTQ2MkYwNTlCMkQ1MTdDNDM2OUYyQzZCM0I5REVFRTIwRjY0NDUxRjgiiwEKQDAyMjZBRjNFMjczQzc4RUE3QUMwQzQxN0NGMzhGQTBFOEIyOEU2NUZGQkUyQ0Q0OEI3NDM1NjY4MjVBRkNCNEYSQDA2M0RCNzdCRTJEMUQ5OTcwNkMyNDQ0ODM5QzM1QzBFMjBEOTJBNEEyMzIwOTlEOTlDMTQ0QTVDNUU3MzM5MjYaBXN0YXJrKpwBCgpjb19zaWduZXIyEgIwMiKJAQpAMDU3RUFBQTE1OEE2MEY3OTcyM0Q3QjhFNDI3QThGRDJDMzZCQ0E0Q0MyODg2Mzk0RjE0RDFDRTc1MjVDN0NDORI-ODIwOUMxQkYxRUUzMzM1QjA1QjZCQUU0Mzg1ODcwOThFM0VEQkU3MzFBRUQxNjQzMjk0OEM5REQ3OTNFMUYaBXN0YXJrKp4BCgpjb19zaWduZXIzEgIwMyKLAQpAMDczRjk2MEY3RUQxRjQwRDE0RUZBNTJFOUNGREQwQjY1QjM2QThCNDM0ODgwNTIzNzU4RDMwRjQ5QjJDNTFFMhJAMDRFREJDMDM1OUExQzkxRTJFQTYyRDhGNEZFOTQ5NDM5OUI3MjM5MDg4MjhFNzcxRDhENzBCRjk5QUY3NjdFMhoFc3RhcmsyiwEKQDA1REUxRERDRTkxMEMwQThGRTg3RDhBOTU5NTE4NkVDOTBGOUUxNDQ2QjkyMDI5QzJEMDFENzIzNDI2RDRBQjcSQDA3MTE2RDRDMTQ3MTU5MTYzOThCQUE0NjlDOTJGODc0MzZGNUExQjBEMDUzRENFN0FFNzJGMzY4N0U2NTYxMUQaBXN0YXJr",
                "EAMYAyLeAQoKY29fc2lnbmVyMhICMDIaQDAxODk2RUVEMjE4NjA2QzFEMEY1RDZEMTU2RUM1RjUzNTMxMjEyMDA5RDA1MTNFNTlGNzlEMTE3ODIzNTYxOUEiiQEKQDA1N0VBQUExNThBNjBGNzk3MjNEN0I4RTQyN0E4RkQyQzM2QkNBNENDMjg4NjM5NEYxNEQxQ0U3NTI1QzdDQzkSPjgyMDlDMUJGMUVFMzMzNUIwNUI2QkFFNDM4NTg3MDk4RTNFREJFNzMxQUVEMTY0MzI5NDhDOURENzkzRTFGGgVzdGFyayqeAQoKY29fc2lnbmVyMRICMDEiiwEKQDAyMjZBRjNFMjczQzc4RUE3QUMwQzQxN0NGMzhGQTBFOEIyOEU2NUZGQkUyQ0Q0OEI3NDM1NjY4MjVBRkNCNEYSQDA2M0RCNzdCRTJEMUQ5OTcwNkMyNDQ0ODM5QzM1QzBFMjBEOTJBNEEyMzIwOTlEOTlDMTQ0QTVDNUU3MzM5MjYaBXN0YXJrKp4BCgpjb19zaWduZXIzEgIwMyKLAQpAMDczRjk2MEY3RUQxRjQwRDE0RUZBNTJFOUNGREQwQjY1QjM2QThCNDM0ODgwNTIzNzU4RDMwRjQ5QjJDNTFFMhJAMDRFREJDMDM1OUExQzkxRTJFQTYyRDhGNEZFOTQ5NDM5OUI3MjM5MDg4MjhFNzcxRDhENzBCRjk5QUY3NjdFMhoFc3RhcmsyiwEKQDA1REUxRERDRTkxMEMwQThGRTg3RDhBOTU5NTE4NkVDOTBGOUUxNDQ2QjkyMDI5QzJEMDFENzIzNDI2RDRBQjcSQDA3MTE2RDRDMTQ3MTU5MTYzOThCQUE0NjlDOTJGODc0MzZGNUExQjBEMDUzRENFN0FFNzJGMzY4N0U2NTYxMUQaBXN0YXJr",
                "EAMYAyLgAQoKY29fc2lnbmVyMxICMDMaQDA0RTJGQ0QxRUQ4OUY5RjhEODNBOUZDOEI5RjlGQkNENUNDNUU4RkIyM0ZBQTdCOEQzNUQ5M0QyRjY2NkI3NEUiiwEKQDA3M0Y5NjBGN0VEMUY0MEQxNEVGQTUyRTlDRkREMEI2NUIzNkE4QjQzNDg4MDUyMzc1OEQzMEY0OUIyQzUxRTISQDA0RURCQzAzNTlBMUM5MUUyRUE2MkQ4RjRGRTk0OTQzOTlCNzIzOTA4ODI4RTc3MUQ4RDcwQkY5OUFGNzY3RTIaBXN0YXJrKp4BCgpjb19zaWduZXIxEgIwMSKLAQpAMDIyNkFGM0UyNzNDNzhFQTdBQzBDNDE3Q0YzOEZBMEU4QjI4RTY1RkZCRTJDRDQ4Qjc0MzU2NjgyNUFGQ0I0RhJAMDYzREI3N0JFMkQxRDk5NzA2QzI0NDQ4MzlDMzVDMEUyMEQ5MkE0QTIzMjA5OUQ5OUMxNDRBNUM1RTczMzkyNhoFc3RhcmsqnAEKCmNvX3NpZ25lcjISAjAyIokBCkAwNTdFQUFBMTU4QTYwRjc5NzIzRDdCOEU0MjdBOEZEMkMzNkJDQTRDQzI4ODYzOTRGMTREMUNFNzUyNUM3Q0M5Ej44MjA5QzFCRjFFRTMzMzVCMDVCNkJBRTQzODU4NzA5OEUzRURCRTczMUFFRDE2NDMyOTQ4QzlERDc5M0UxRhoFc3RhcmsyiwEKQDA1REUxRERDRTkxMEMwQThGRTg3RDhBOTU5NTE4NkVDOTBGOUUxNDQ2QjkyMDI5QzJEMDFENzIzNDI2RDRBQjcSQDA3MTE2RDRDMTQ3MTU5MTYzOThCQUE0NjlDOTJGODc0MzZGNUExQjBEMDUzRENFN0FFNzJGMzY4N0U2NTYxMUQaBXN0YXJr"
    };
    testKeyRefresh(minimal_sign_key_base64_arr_3);
#endif
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
