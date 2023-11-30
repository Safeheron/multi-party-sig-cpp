
#include <vector>
#include "crypto-suites/crypto-sss/vsss.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-hash/safe_hash256.h"
#include "crypto-suites/crypto-encode/hex.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/round0.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/security_param.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/context.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::sss::Polynomial;
using safeheron::multi_party_ecdsa::cmp::SignKey;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::curve::CurveType;
using safeheron::hash::CSafeHash256;
using safeheron::zkp::pail::PailEncRangeSetUp_V2;
using safeheron::zkp::pail::PailEncRangeStatement_V2;
using safeheron::zkp::pail::PailEncRangeProof_V2;


namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace sign {

bool Round0::ComputeVerify() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;
    const safeheron::curve::Curve * curv = ctx->GetCurrentCurve();

    // Sample k_i, \gamma_i in Zq
    ctx->local_party_.k_ = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.gamma_ = safeheron::rand::RandomBNLt(curv->n);

    // Sample \rho_i, \nu_i in ZN*
    ctx->local_party_.rho_ = safeheron::rand::RandomBNLtCoPrime(ctx->local_party_.pail_pub_.n());
    ctx->local_party_.nu_ = safeheron::rand::RandomBNLtCoPrime(ctx->local_party_.pail_pub_.n());

    // \Gamma_i = g * \gamma_i
    ctx->local_party_.Gamma_ = curv->g * ctx->local_party_.gamma_;

    // G_i = enc_i(\gamma_i, \nu_i)
    ctx->local_party_.G_ = ctx->local_party_.pail_pub_.EncryptNegWithR(ctx->local_party_.gamma_, ctx->local_party_.nu_);
    // K_i = enc_i(\k_i, \rho_i)
    ctx->local_party_.K_ = ctx->local_party_.pail_pub_.EncryptNegWithR(ctx->local_party_.k_, ctx->local_party_.rho_);

    // MTA(k, gamma) / MTA(k, x)   - step 1
    // Party i prove to party j that K_i = enc_i(\k_i, \rho_i),  i != j
    for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
        PailEncRangeSetUp_V2 setup(sign_key.remote_parties_[j].N_,
                                   sign_key.remote_parties_[j].s_,
                                   sign_key.remote_parties_[j].t_);
        PailEncRangeStatement_V2 statement(ctx->local_party_.K_,
                                           ctx->local_party_.pail_pub_.n(),
                                           ctx->local_party_.pail_pub_.n_sqr(),
                                           curv->n,
                                           SECURITY_PARAM_L,
                                           SECURITY_PARAM_EPSILON);
        zkp::pail::PailEncRangeWitness_V2 witness(ctx->local_party_.k_,
                                                  ctx->local_party_.rho_);
        ctx->remote_parties_[j].psi_0_ji_.SetSalt(ctx->local_party_.ssid_index_);
        ctx->remote_parties_[j].psi_0_ji_.Prove(setup, statement, witness);
    }

    return true;
}

bool Round0::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                             std::vector<std::string> &out_des_arr) const {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
        out_des_arr.push_back(sign_key.remote_parties_[j].party_id_);
    }

    for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
        Round0P2PMessage p2p_message;
        p2p_message.ssid_ = ctx->ssid_;
        p2p_message.index_ = sign_key.local_party_.index_;
        p2p_message.psi_0_ij_ = ctx->remote_parties_[j].psi_0_ji_;
        string base64;
        ok = p2p_message.ToBase64(base64);
        if (!ok) {
            ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to encode to base64!");
            return false;
        }
        out_p2p_msg_arr.push_back(base64);
    }

    Round0BCMessage bc_message;
    bc_message.ssid_ = ctx->ssid_;
    bc_message.index_ = sign_key.local_party_.index_;
    bc_message.K_ = ctx->local_party_.K_;
    bc_message.G_ = ctx->local_party_.G_;
    ok = bc_message.ToBase64(out_bc_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in bc_message.ToBase64(out_bc_msg)!");
        return false;
    }

    return true;
}

}
}
}
}