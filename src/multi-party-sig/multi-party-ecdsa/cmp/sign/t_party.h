

#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_T_PARTY_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_T_PARTY_H


#include "crypto-suites/crypto-sss/vsss.h"
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-paillier/pail.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-zkp/zkp.h"
#include "crypto-suites/crypto-commitment/commitment.h"
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "multi-party-sig/mpc-flow/mpc-parallel/LazyBCValidator.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/proto_gen/sign.pb.switch.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace sign {


class LocalTParty {
public:
    // (ssid, index)
    std::string ssid_index_;
    // Sample in F_q
    safeheron::bignum::BN k_;
    safeheron::bignum::BN gamma_;
    safeheron::curve::CurvePoint Gamma_;

    // Sample in Z_N*
    safeheron::bignum::BN rho_;
    safeheron::bignum::BN nu_;

    // Paillier Key Pair
    safeheron::pail::PailPubKey pail_pub_;
    safeheron::pail::PailPrivKey pail_priv_;

    safeheron::bignum::BN G_; // enc(r; mu)
    safeheron::bignum::BN K_; // enc(k; rho)

    safeheron::bignum::BN D_ij;
    safeheron::bignum::BN D_hat_ij;
    safeheron::bignum::BN F_ij;     // enc(beta; r)
    safeheron::bignum::BN F_hat_ij; // enc(beta; r_hat)

    safeheron::curve::CurvePoint Delta_;

    safeheron::bignum::BN chi_;
    safeheron::bignum::BN delta_;

    safeheron::bignum::BN sigma_;
};

class RemoteTParty {
public:
    // (ssid, index)
    std::string ssid_index_;
    /***************** from remote party ************************/
    safeheron::bignum::BN G_; // enc(r; mu)
    safeheron::bignum::BN K_; // enc(k; rho)
    safeheron::zkp::pail::PailEncRangeProof_V2 psi_0_ji_; // M( prove, (K); (k, rho) )

    /***************** to remote party ************************/
    safeheron::bignum::BN D_ji;
    safeheron::bignum::BN D_hat_ji;
    safeheron::bignum::BN F_ji;     // enc(beta; r)
    safeheron::bignum::BN F_hat_ji; // enc(beta; r_hat)

    safeheron::bignum::BN recv_D_ij;
    safeheron::bignum::BN recv_D_hat_ij;
    safeheron::bignum::BN recv_F_ij;     // enc(beta; r)
    safeheron::bignum::BN recv_F_hat_ij; // enc(beta; r_hat)

    safeheron::curve::CurvePoint Gamma_;

    // Paillier Key Pair
    safeheron::pail::PailPubKey pail_pub_;

    // Sample in Z_N
    safeheron::bignum::BN r_ij_;
    safeheron::bignum::BN s_ij_;
    safeheron::bignum::BN r_hat_ij_;
    safeheron::bignum::BN s_hat_ij_;

    // Sample in J
    safeheron::bignum::BN beta_ij_;
    safeheron::bignum::BN beta_hat_ij_;

    safeheron::bignum::BN beta_tag_ij_;
    safeheron::bignum::BN beta_tag_hat_ij_;

    safeheron::zkp::pail::PailAffGroupEleRangeProof_V2 psi_ji_; // M( prove, (D_ij, K, F_ij, T); (r_ij, beta_ij, s_ij, r_ij) )
    safeheron::zkp::pail::PailAffGroupEleRangeProof_V2 psi_hat_ji_; // M( prove, (D_hat_ij, K, F_hat_ij, T); (x, beta_hat_ij, s_hat_ij, r_hat_ij) )
    safeheron::zkp::pail::PailEncGroupEleRangeProof psi_prime_ji_; // M( prove, (Gamma); (k, rho) )

    safeheron::bignum::BN alpha_ij_;
    safeheron::bignum::BN alpha_hat_ij_;

    safeheron::curve::CurvePoint Delta_;

    safeheron::bignum::BN chi_;
    safeheron::bignum::BN delta_;
    safeheron::bignum::BN raw_delta_;

    safeheron::zkp::pail::PailEncGroupEleRangeProof psi_double_prime_ji_; // M( prove, (Gamma); (k, rho) )

    safeheron::bignum::BN sigma_;
};

}
}
}
}


#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_T_PARTY_H
