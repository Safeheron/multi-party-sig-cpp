#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign/round4.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign/context.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::sss::Polynomial;
using safeheron::multi_party_ecdsa::gg18::SignKey;

static BN POW2_256 = BN(1) << 256;

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{
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

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    bool ok = bc_message_arr_[pos].dlog_proof_gamma_.Verify();
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to verify schnorr proof of gamma!");
        return false;
    }

    BN commitment = safeheron::commitment::CreateComWithBlind(bc_message_arr_[pos].dlog_proof_gamma_.pk_, bc_message_arr_[pos].blind_factor_);
    ok = (commitment == ctx->remote_parties_[pos].commitment_Gamma_);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to verify commitment of g^gamma!");
        return false;
    }

    ctx->remote_parties_[pos].Gamma_ = bc_message_arr_[pos].dlog_proof_gamma_.pk_;

    return true;
}

bool Round4::ComputeVerify() {
    bool ok = true;
    // Validate child private key share
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    CurvePoint R = curv->g * ctx->local_party_.gamma_;
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        R += ctx->remote_parties_[i].Gamma_;
    }

    R = R * ctx->delta_.InvM(curv->n);

    ctx->R_ = R;
    ctx->r_ = R.x() % curv->n;
    // s_i = m * k_i + r * sigma_i
    BN si = (ctx->m_ * ctx->local_party_.k_ + ctx->r_ * ctx->local_party_.sigma_) % curv->n;
    ctx->local_party_.si_ = si;

    // Sample l, rho in Z_q
    ctx->local_party_.l_ = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.rho_ = safeheron::rand::RandomBNLt(curv->n);
    // V_i = R^s_i * g^l_i
    ctx->local_party_.V_ = R * si + curv->g * ctx->local_party_.l_;
    // A_i = g^rho_i
    ctx->local_party_.A_ = curv->g * ctx->local_party_.rho_;

    // Commitment(Vi, Ai)
    vector<CurvePoint> points;
    points.push_back(ctx->local_party_.V_);
    points.push_back(ctx->local_party_.A_);
    ctx->local_party_.blind_factor_2_ = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.commitment_VA_ = safeheron::commitment::CreateComWithBlind(points, ctx->local_party_.blind_factor_2_);

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

    Round4BCMessage bc_message;
    bc_message.commitment_ = ctx->local_party_.commitment_VA_;
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
