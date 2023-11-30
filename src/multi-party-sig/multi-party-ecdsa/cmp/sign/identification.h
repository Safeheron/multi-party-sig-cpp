
#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_IDENTIFICATION_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_IDENTIFICATION_H

#include <string>
#include <vector>
#include "crypto-suites/crypto-zkp/zkp.h"
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/proto_gen/sign.pb.switch.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace sign {

class StoreState{
    std::string ssid;
    safeheron::bignum::BN index;
    safeheron::curve::CurvePoint R;
    safeheron::bignum::BN k;
    safeheron::bignum::BN chi;
};

class ProofInPreSignPhase {
public:
    // Enc(k * gamma)
    safeheron::bignum::BN c_k_gamma_;
    // For all l \eq i,j, namely n - 2 in total, prove that {D_ji} are well-formed in ZK{aff-g}
    std::map<std::string, std::map<std::string, safeheron::zkp::pail::PailAffGroupEleRangeProof_V2>> id_map_map_;
    // In Pre-Signing phase, prove that H_i = enc_i(k_i · gamma_i) is well formed wrt K_i and G_i in ZK{mul}
    safeheron::zkp::pail::PailEncMulProof pail_enc_mul_proof_;
    // In Pre-Signing phase, for all l \eq i  , namely n - 1 in total, prove that δ_i is the plaintext value mod q of the ciphertext obtained as H_i * \PI_{j ≠ i} {D_ij * F_ji} in ZK{dec}
    std::map<std::string, safeheron::zkp::pail::PailDecModuloProof> id_dec_proof_map_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::sign::ProofInPreSignPhase &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::sign::ProofInPreSignPhase &message);

    bool ToBase64(std::string &base64) const;

    bool FromBase64(const std::string &base64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class ProofInSignPhase {
public:
    // Enc(k * gamma)
    safeheron::bignum::BN c_k_x_;
    // For all l \eq i,j, namely n - 2 in total, prove that {D_ji} are well-formed in ZK{aff-g}
    std::map<std::string, std::map<std::string, safeheron::zkp::pail::PailAffGroupEleRangeProof_V2>> id_map_map_;
    // In Signing phase, prove that H_i = enc_i(k_i · x_i) is well formed wrt K_i and X_i in ZK{mul}
    std::map<std::string, safeheron::zkp::pail::PailMulGroupEleRangeProof> id_mul_group_ele_proof_map_;
    // In Signing phase, for all l \eq i  , namely n - 1 in total, prove that sigma_i is the plaintext value mod q of the ciphertext obtained as K_i^m * (H_hat_i * \PI_{j ≠ i} {D_hat_ij * F_hat_ji})^r in ZK{dec}
    std::map<std::string, safeheron::zkp::pail::PailDecModuloProof> id_dec_proof_map_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::sign::ProofInSignPhase &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::sign::ProofInSignPhase &message);

    bool ToBase64(std::string &base64) const;

    bool FromBase64(const std::string &base64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};


}
}
}
}


#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_IDENTIFICATION_H
