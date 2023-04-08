

#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_ONCE_T_PARTY_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_ONCE_T_PARTY_H


#include "proto_gen/sign.pb.switch.h"
#include "crypto-sss/vsss.h"
#include "crypto-bn/bn.h"
#include "crypto-paillier/pail.h"
#include "crypto-curve/curve.h"
#include "crypto-zkp/zkp.h"
#include "mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "mpc-flow/mpc-parallel/LazyBCValidator.h"
#include "crypto-commitment/commitment.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace sign {


class LocalTParty {
public:
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
    /***************** from remote party ************************/
    safeheron::bignum::BN G_; // enc(r; mu)
    safeheron::bignum::BN K_; // enc(k; rho)
    safeheron::zkp::pail::PailEncRangeProof_V2 psi_0_ij_; // M( prove, (K); (k, rho) )

    /***************** to remote party ************************/
    safeheron::bignum::BN D_ij;
    safeheron::bignum::BN D_hat_ij;
    safeheron::bignum::BN F_ij;     // enc(beta; r)
    safeheron::bignum::BN F_hat_ij; // enc(beta; r_hat)

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

    safeheron::zkp::pail::PailAffGroupEleRangeProof_V2 psi_ij_; // M( prove, (D_ij, K, F_ij, T); (r_ij, beta_ij, s_ij, r_ij) )
    safeheron::zkp::pail::PailAffGroupEleRangeProof_V2 psi_hat_ij_; // M( prove, (D_hat_ij, K, F_hat_ij, T); (x, beta_hat_ij, s_hat_ij, r_hat_ij) )
    safeheron::zkp::pail::PailEncGroupEleRangeProof psi_prime_ij_; // M( prove, (Gamma); (k, rho) )

    safeheron::bignum::BN alpha_ij_;
    safeheron::bignum::BN alpha_hat_ij_;

    safeheron::curve::CurvePoint Delta_;

    safeheron::bignum::BN chi_;
    safeheron::bignum::BN delta_;

    safeheron::zkp::pail::PailEncGroupEleRangeProof psi_double_prime_ij_; // M( prove, (Gamma); (k, rho) )

    safeheron::bignum::BN sigma_;
};

}
}
}
}


#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_ONCE_T_PARTY_H
