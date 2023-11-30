#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "multi-party-sig/multi-party-ecdsa/gg20/sign/round4.h"
#include "multi-party-sig/multi-party-ecdsa/gg20/sign/context.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::sss::Polynomial;
using safeheron::multi_party_ecdsa::gg18::SignKey;
using safeheron::zkp::pail::PailEncGroupEleRangeSetUp;
using safeheron::zkp::pail::PailEncGroupEleRangeStatement;
using safeheron::zkp::pail::PailEncGroupEleRangeWitness;
using safeheron::zkp::pail::PailEncGroupEleRangeProof;

static BN POW2_256 = BN(1) << 256;

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg20{
namespace sign{

void Round4::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        bc_message_arr_.emplace_back();
    }
}

bool Round4::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    bool ok = bc_message_arr_[pos].FromBase64(bc_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64!");
        return false;
    }


    return true;
}

bool Round4::ReceiveVerify(const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    BN commitment = safeheron::commitment::CreateComWithBlind(bc_message_arr_[pos].Gamma_, bc_message_arr_[pos].blind_factor_);
    bool ok = (commitment == ctx->remote_parties_[pos].com_Gamma_);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to verify commitment of g^gamma!");
        return false;
    }

    ctx->remote_parties_[pos].Gamma_ = bc_message_arr_[pos].Gamma_;

    return true;
}

bool Round4::ComputeVerify() {
    bool ok = true;
    // Validate child private key share
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    // sum{Gamma_i}
    CurvePoint R = ctx->local_party_.Gamma_;
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        R += ctx->remote_parties_[i].Gamma_;
    }

    R = R * ctx->delta_.InvM(curv->n);

    ctx->R_ = R;
    ctx->r_ = R.x() % curv->n;
    // s_i = m * k_i + r * sigma_i
    BN si = (ctx->m_ * ctx->local_party_.k_ + ctx->r_ * ctx->local_party_.sigma_) % curv->n;
    ctx->local_party_.sig_share_ = si;

    ctx->local_party_.Ri_ = R * ctx->local_party_.k_;

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        PailEncGroupEleRangeSetUp setup(sign_key.remote_parties_[i].N_tilde_,
                sign_key.remote_parties_[i].h1_,
                sign_key.remote_parties_[i].h2_);

        PailEncGroupEleRangeStatement statement(ctx->local_party_.message_a_,
                                                sign_key.local_party_.pail_pub_.n(),
                                                sign_key.local_party_.pail_pub_.n_sqr(),
                                                curv->n,
                                                ctx->local_party_.Ri_,
                                                R,
                                                256, 512);
        PailEncGroupEleRangeWitness witness(ctx->local_party_.k_, ctx->local_party_.r_for_pail_for_mta_msg_a_);
        ctx->remote_parties_[i].pail_enc_group_ele_range_proof_.Prove(setup, statement, witness);
    }

    return true;
}

bool Round4::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                             std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        out_des_arr.push_back(sign_key.remote_parties_[i].party_id_);
    }

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        Round4P2PMessage p2p_message;
        p2p_message.pail_enc_group_ele_range_proof_ = ctx->remote_parties_[i].pail_enc_group_ele_range_proof_;
        string base64;
        bool ok = p2p_message.ToBase64(base64);
        if (!ok) {
            ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to encode to base64!");
            return false;
        }
        out_p2p_msg_arr.push_back(base64);
    }

    Round4BCMessage bc_message;
    bc_message.R_ = ctx->local_party_.Ri_;
    bool ok = bc_message.ToBase64(out_bc_msg);
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
