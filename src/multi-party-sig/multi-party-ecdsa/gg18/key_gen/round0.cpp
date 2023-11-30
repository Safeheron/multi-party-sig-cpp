#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_gen/round0.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_gen/context.h"

using std::string;

namespace safeheron {
namespace multi_party_ecdsa {
namespace gg18 {
namespace key_gen {

bool Round0::ComputeVerify() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;
    const curve::Curve *curv = curve::GetCurveParam(ctx->curve_type_);

    // Sample u \in Z_q
    ctx->local_party_.u_ = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.y_ = curv->g * ctx->local_party_.u_;

    // Commitment: KGC, KGD of Yi
    ctx->local_party_.kgd_y_.point_ = ctx->local_party_.y_;
    ctx->local_party_.kgd_y_.blind_factor_ = safeheron::rand::RandomBN(256);
    ctx->local_party_.kgc_y_ = safeheron::commitment::CreateComWithBlind(ctx->local_party_.y_,
                                                                         ctx->local_party_.kgd_y_.blind_factor_);

    // Generate Paillier key pair
    CreateKeyPair2048(sign_key.local_party_.pail_priv_, sign_key.local_party_.pail_pub_);

    // Generate (N_tilde, h1, h2)
    safeheron::zkp::dln_proof::GenerateN_tilde(sign_key.local_party_.N_tilde_,
                                               sign_key.local_party_.h1_,
                                               sign_key.local_party_.h2_,
                                               sign_key.local_party_.p_,
                                               sign_key.local_party_.q_,
                                               sign_key.local_party_.alpha_,
                                               sign_key.local_party_.beta_);
    // DLN Proof
    ctx->local_party_.dln_proof1_.Prove(sign_key.local_party_.N_tilde_,
                                        sign_key.local_party_.h1_,
                                        sign_key.local_party_.h2_,
                                        sign_key.local_party_.p_,
                                        sign_key.local_party_.q_,
                                        sign_key.local_party_.alpha_);
    ctx->local_party_.dln_proof2_.Prove(sign_key.local_party_.N_tilde_,
                                        sign_key.local_party_.h2_,
                                        sign_key.local_party_.h1_,
                                        sign_key.local_party_.p_,
                                        sign_key.local_party_.q_,
                                        sign_key.local_party_.beta_);

    return true;
}

bool Round0::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                         std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        out_des_arr.push_back(sign_key.remote_parties_[i].party_id_);
    }

    Round0BCMessage message;
    message.kgc_y_ = ctx->local_party_.kgc_y_;
    message.dln_proof_1_ = ctx->local_party_.dln_proof1_;
    message.dln_proof_2_ = ctx->local_party_.dln_proof2_;
    message.N_tilde_ = sign_key.local_party_.N_tilde_;
    message.h1_ = sign_key.local_party_.h1_;
    message.h2_ = sign_key.local_party_.h2_;
    message.index_ = sign_key.local_party_.index_;
    message.pail_pub_ = sign_key.local_party_.pail_pub_;
    message.ToBase64(out_bc_msg);

    return true;
}

}
}
}
}
