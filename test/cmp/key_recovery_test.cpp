#include "multi-party-sig/multi-party-ecdsa/cmp/key_recovery/context.h"
#include <string>
#include <vector>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-suites/crypto-sss/polynomial.h"
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "../CTimer.h"
#include "../message.h"

bool key_recovery_test(safeheron::curve::CurveType c_type, const safeheron::bignum::BN &index_1, const safeheron::bignum::BN &index_2, const safeheron::bignum::BN &index_3, const safeheron::bignum::BN &x_1, const safeheron::bignum::BN &x_2, safeheron::bignum::BN &x_lost) {
    //2-3 key recovery, total_parties == 2
    int total_parties = 2;

    std::string party_id_1 = "party_1";
    std::string party_id_2 = "party_2";

    safeheron::multi_party_ecdsa::cmp::key_recovery::Context ctx_1;
    bool ok = safeheron::multi_party_ecdsa::cmp::key_recovery::Context::CreateContext(ctx_1, c_type, x_1, index_1, index_2, index_3, party_id_1, party_id_2);
    if (!ok) return false;

    safeheron::multi_party_ecdsa::cmp::key_recovery::Context ctx_2;
    ok = safeheron::multi_party_ecdsa::cmp::key_recovery::Context::CreateContext(ctx_2, c_type, x_2, index_2, index_1, index_3, party_id_2, party_id_1);
    if (!ok) return false;

    std::vector<safeheron::multi_party_ecdsa::cmp::key_recovery::Context*> ctx_arr = {&ctx_1, &ctx_2};

    CTimer t("KeyRecovery");

    //two parties
    std::map<std::string, std::vector<Msg>> map_id_message_queue;
    for (int round = 0; round <= 3; ++round) {
        for (size_t i = 0; i < ctx_arr.size(); ++i) {
            if (round == 0) {
                ok = ctx_arr[i]->PushMessage();
                if (!ok) return false;
            } else {
                std::vector<Msg>::iterator iter = map_id_message_queue[ctx_arr[i]->local_party_.party_id_].begin();
                for (int j = 0; j < total_parties -1; ++j) {
                    ok = ctx_arr[i]->PushMessage(iter->p2p_msg_, iter->bc_msg_, iter->src_, round - 1);
                    if (!ok) return false;
                    iter = map_id_message_queue[ctx_arr[i]->local_party_.party_id_].erase(iter);
                }
            }
            if (!ctx_arr[i]->IsCurRoundFinished()) return false;

            std::vector<std::string> out_p2p_message_arr;
            std::string out_broadcast_message;
            std::vector<std::string> out_des_arr;
            ok = ctx_arr[i]->PopMessages(out_p2p_message_arr, out_broadcast_message, out_des_arr);
            if (!ok) return false;

            for (size_t k = 0; k < out_des_arr.size(); ++k) {
                map_id_message_queue[out_des_arr[k]].push_back({ctx_arr[i]->local_party_.party_id_,
                                                                out_broadcast_message,
                                                                out_p2p_message_arr.empty() ? std::string():out_p2p_message_arr[k]
                                                               });
            }
        }
    }

    for (size_t i = 0; i < ctx_arr.size(); ++i) {
        if (!ctx_arr[i]->IsFinished()) {
            return false;
        }
    }

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam( c_type);
    x_lost = (ctx_1.x_ki_ + ctx_2.x_ki_) % curv->n;
    safeheron::curve::CurvePoint X_lost = curv->g * x_lost;
    EXPECT_TRUE(X_lost == ctx_1.X_k_);
    EXPECT_TRUE(X_lost == ctx_2.X_k_);

    t.End();

    return true;
}

TEST(key_recovery_test, verify_test) {
    safeheron::bignum::BN index_1(1);
    safeheron::bignum::BN index_2(2);
    safeheron::bignum::BN index_3(3);
    //secp256k1
    std::vector<std::string> shard_1 = {
            "D2D065CB8C079E3B335FC06F5B2A1D04E3E1A880F95527C0CCEE9EADE00A99E9",
            "4A41226185C3A0F6DECA01DA39ECF022AAB884E3D8A2C12B940635BBA0CC47C0",
            "E08F849218FA54FFBFBFD7BD808C6CEC3B6C4B190AEBC5FBD943DDCD549CA45C",
            "FD894F29E9013DE8D8950C54B474A5AE136C1DC2B9A1D58C5060EB6EC0931E82",
            "D7C3DF1136BBCE8354CB996FE580C4036E52987D2B98E3C9DEC3236FB7D0DAAA",
            "1DA891941D5069964B0B934E2440EEF34339B4FE72723A424C802EF4414EE892",
            "37AC217C9A3CF4040D82A4B2A7DA179FF469D747E6491E328AE5130DF2739F12",
            "1F17731C1BE7077B04132C634235C06B134633BA283B9FFBEF2C7699945BD036",
            "0296AEEBA92F90FA0A2DE4E0076504AC934FE4868BBFE15714E59B1EDAA91B00",
            "1D33E970E8BF566466BE5EABDC44AD625E88CBFBE4DA7FF2843AD0B39C7A8ADA"
    };
    std::vector<std::string> shard_2 = {
            "47A15FF47A7E2FFAFA0300364B872FF4C1A446FDA9CE82BB9F412530F72BDC3F",
            "AA1B9661D86CA05D62D935809AFACAA33B1431D2C861A7A1F3E7152A58CCFADB",
            "E70A52D06DF27335F9CEB534B678B8A0ACBDF6D04F552E69DF6F2E3DD41EFF5D",
            "1E5D6D075906BD28C71BB4785FF3D1F7F970EF702188A1EFDAE3A11164471D88",
            "B97A35B42B0F9D8A2DEC5A180EB6C21121B8B2185949C9B258D3C4FD52BB0875",
            "9D3C2E4393E572EBA0665FD8C0197F4D8E42939758D3C3A927A459B685072198",
            "79CA0ED1D7BBD62959784180080A747737D0FE4BD097935B62E7A51BA2AB13EA",
            "603413A398A0683A8C5FD5D7E179A663E81DE416AFD60589D84ADC30A8BEC7E5",
            "B46B0B3B27384972749BFB464CB6E6008B521531D8D38FCF180A8016C1B34483",
            "AEEF0D7D1FB0AAA84933009A11699C86D083742799DFA32F5A5BBB84D3F52E3E"
    };
    std::vector<std::string> shard_3 = {
            "BC725A1D68F4C1BAC0A63FFD3BE442E35A15C26109907DF231660A40DE835FD6",
            "09F60A622B159FC3E6E86926FC08A52510C101DB08D7EDDC93F5960C40976CB5",
            "ED85210EC2EA916C33DD92ABEC6504551E0FA28793BE96D7E59A7EAE53A15A5E",
            "3F318AE4C90C3C68B5A25C9C0B72FE409A249E0438B80E8F2538B540D8315DCF",
            "9B308C571F636C91070D1AC037ECC01ED51ECBB386FAAF9AD2E4668AEDA53640",
            "1CCFCAF30A7A7C40F5C12C635BF20FA91E9C95498FECACD442F625EBF889195D",
            "BBE7FC27153AB84EA56DDE4D683AD14E7B38254FBAE608843AEA372952E288C2",
            "A150B42B1559C8FA14AC7F4C80BD8C5CBCF5947337706B17C16941C7BD21BF94",
            "663F678AA54101EADF0A11AC9208C755C8A568F6769E9E0B5B5D0681D8872CC5",
            "40AA318956A1FEEC2BA7A288468E8BAC87CF3F6C9F9C263070AA47C93B399061"
    };
    for (size_t i = 0; i < shard_1.size(); ++i) {
        safeheron::bignum::BN x_1 = safeheron::bignum::BN::FromHexStr(shard_1[i]);
        safeheron::bignum::BN x_2 = safeheron::bignum::BN::FromHexStr(shard_2[i]);
        safeheron::bignum::BN x_3;
        bool ok = key_recovery_test(safeheron::curve::CurveType::SECP256K1, index_1, index_2, index_3, x_1, x_2, x_3);
        EXPECT_TRUE(ok);
        safeheron::bignum::BN expected_x3 = safeheron::bignum::BN::FromHexStr(shard_3[i]);
        EXPECT_TRUE(x_3 == expected_x3);
    }

    //ed25519
    shard_1 = {
        "07514903C86FFF45D42F0AF98D1C7929FFE828277579C9C5F0C18A45CBFD1CD5",
        "0F8CC9F4DE14F6B157C8EF1284BB6F951FF1528098557D54A8E4704269D8A4EA",
        "057863A7107E5B40B4BF3B4CAFCFFB0CFBD6BC378E5A25E6CDEEF299042AD6FC",
        "013501E219DA196CF49BD9F4125586FD8565D88E3B4998B3AD82B7BA9FEE8DF4",
        "04CD21CAE06E61539096B150EE8297E42ED91F98874FABCFC2CCC56F0734665F",
        "0E013C1716906131878422245CDCC588D1DE6444F90FB80DC08822E3A40FE0CA",
        "0FD9D8AAE5F93089DE88D68DF42A0A73C1516FD4D6812D532649C259229C9069",
        "080D14EB6EF4F31D6AC906A8DB93B79F0AC4AD9FAB755F7A919E32429ED970A9",
        "07429E2DC883ECFF6A3DE4C316D03007E8A50A2D0282D2D327B88201A601075C",
        "0DB69E2DD8D16F20BE11F561FC5A74B86D1158AF5F80FDC65B44DE9DB562DD5F"
    };
    shard_2 = {
        "2ABBCB73592C3C0239C129A7811FF257BF052EF412E4320663B253B6C280DF",
        "0CE8B463C8384DD11EF3CB1F7CA11630D357F371C2FE358D64A7E03312BD3351",
        "0656AA536241196F81A3DA0A852FDE560C7F3C5F0F17F7C43A91954127529481",
        "058064C4E2714D6523ACB6506758BC378DC2C5C3015B0FCFE1003C82A0A95BCD",
        "07F45CBA14D6FB692D23752BE9154400C3B075AAB152F17034B5F49D3118C37E",
        "08BDE1D2D6C1CFDB2C3C987AA3DCF2736DAA15869D9D9CA7944204D6FC20FE8F",
        "0550CF35A39A8514A31ACEA7C0B3690EE95672CBF05E7664123E9B87585D0D2F",
        "0CA9BC40446A597EB80058020FA0D7181E580205ABE6DA32538B2BC498DF2D3B",
        "0A4F0FEF401DEF5DC360483AB784669BBAF1421C2850BCDFE23C1E4E3855803A",
        "0C7314BD5E4EA9F67CE9A57E7DAE4FE939E930BC02831390230D251594010D19"
    };
    shard_3 = {
        "09042E931E42593230447759C1E5C6BAC474DC1515A39B7474183D7BFE7DB8D6",
        "0A449ED2B25BA4F0E61EA72C7486BCCC86BE9462EDA6EDC6206B5023BBA1C1B8",
        "0734F0FFB403D79E4E8878C85A8FC19F1D27BC868FD5C9A1A73437E94A7A5206",
        "09CBC7A7AB08815D52BD92ACBC5BF171961FB2F7C76C86EC147DC14AA16429A6",
        "0B1B97A9493F957EC9B03906E3A7F01D5887CBBCDB563710A69F23CB5AFD209D",
        "037A878E96F33E84D0F50ED0EADD1F5E0975C6C8422B814167FBE6CA54321C54",
        "0AC7C5C0613BD99F67ACC6C18D3CC7AA263A6FA1AD335C4B5645D7CFEB135DE2",
        "0146639519DFBFE00537A95B43ADF6911D0C5C8D0960B813BD65C22C35EF15E0",
        "0D5B81B0B7B7F1BC1C82ABB258389D2F8D3D7A0B4E1EA6EC9CBFBA9ACAA9F918",
        "0B2F8B4CE3CBE4CC3BC1559AFF022B1A06C108C8A5852959EAD56B8D729F3CD3"
    };
    for (size_t i = 0; i < shard_1.size(); ++i) {
        safeheron::bignum::BN x_1 = safeheron::bignum::BN::FromHexStr(shard_1[i]);
        safeheron::bignum::BN x_2 = safeheron::bignum::BN::FromHexStr(shard_2[i]);
        safeheron::bignum::BN x_3;
        bool ok = key_recovery_test(safeheron::curve::CurveType::ED25519, index_1, index_2, index_3, x_1, x_2, x_3);
        EXPECT_TRUE(ok);
        safeheron::bignum::BN expected_x3 = safeheron::bignum::BN::FromHexStr(shard_3[i]);
        EXPECT_TRUE(x_3 == expected_x3);
    }
}

TEST(key_recovery_test, benchmark) {
    //secp256k1
    for (int i = 0; i < 1000; ++i) {
        const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam( safeheron::curve::CurveType::SECP256K1);
        safeheron::bignum::BN index_1(1);
        safeheron::bignum::BN index_2(2);
        safeheron::bignum::BN index_3(3);

        std::vector<safeheron::bignum::BN> index_arr;
        index_arr.push_back(index_1);
        index_arr.push_back(index_2);
        index_arr.push_back(index_3);
        std::vector<safeheron::bignum::BN> l_arr;
        safeheron::sss::Polynomial::GetLArray(l_arr, safeheron::bignum::BN::ZERO, index_arr, curv->n);

        index_arr.clear();
        index_arr.push_back(index_1);
        index_arr.push_back(index_2);
        std::vector<safeheron::bignum::BN> l_arr_i_j;
        safeheron::sss::Polynomial::GetLArray(l_arr_i_j, safeheron::bignum::BN::ZERO, index_arr, curv->n);

        safeheron::bignum::BN x_1 = safeheron::rand::RandomBNLt(curv->n);
        safeheron::bignum::BN x_2 = safeheron::rand::RandomBNLt(curv->n);
        safeheron::bignum::BN x_3;
        bool ok = key_recovery_test(safeheron::curve::CurveType::SECP256K1, index_1, index_2, index_3, x_1, x_2, x_3);
        EXPECT_TRUE(ok);
        safeheron::bignum::BN tmp = l_arr_i_j[0] * x_1 + l_arr_i_j[1] * x_2 - (l_arr[0] * x_1 + l_arr[1] * x_2);
        safeheron::bignum::BN expected_x3 = (l_arr[2].InvM(curv->n) * tmp) % curv->n;
        EXPECT_TRUE(x_3 == expected_x3);
    }

    //ed25519
    for (int i = 0; i < 1000; ++i) {
        const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam( safeheron::curve::CurveType::ED25519);
        safeheron::bignum::BN index_1(1);
        safeheron::bignum::BN index_2(2);
        safeheron::bignum::BN index_3(3);

        std::vector<safeheron::bignum::BN> index_arr;
        index_arr.push_back(index_1);
        index_arr.push_back(index_2);
        index_arr.push_back(index_3);
        std::vector<safeheron::bignum::BN> l_arr;
        safeheron::sss::Polynomial::GetLArray(l_arr, safeheron::bignum::BN::ZERO, index_arr, curv->n);

        index_arr.clear();
        index_arr.push_back(index_1);
        index_arr.push_back(index_2);
        std::vector<safeheron::bignum::BN> l_arr_i_j;
        safeheron::sss::Polynomial::GetLArray(l_arr_i_j, safeheron::bignum::BN::ZERO, index_arr, curv->n);

        safeheron::bignum::BN x_1 = safeheron::rand::RandomBNLt(curv->n);
        safeheron::bignum::BN x_2 = safeheron::rand::RandomBNLt(curv->n);
        safeheron::bignum::BN x_3;
        bool ok = key_recovery_test(safeheron::curve::CurveType::ED25519, index_1, index_2, index_3, x_1, x_2, x_3);
        EXPECT_TRUE(ok);
        safeheron::bignum::BN tmp = l_arr_i_j[0] * x_1 + l_arr_i_j[1] * x_2 - (l_arr[0] * x_1 + l_arr[1] * x_2);
        safeheron::bignum::BN expected_x3 = (l_arr[2].InvM(curv->n) * tmp) % curv->n;
        EXPECT_TRUE(x_3 == expected_x3);
    }
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}

