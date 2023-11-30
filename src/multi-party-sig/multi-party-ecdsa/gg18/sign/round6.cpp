#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign/round6.h"
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

void Round6::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        bc_message_arr_.emplace_back();
    }
}

bool Round6::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
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

bool Round6::ReceiveVerify(const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    zkp::linear_combination::LinearCombinationStatement lc_proof_statement_VRG(bc_message_arr_[pos].V_,ctx->R_,curv->g,curv->n);
    bool ok = bc_message_arr_[pos].lc_proof_VRG_.Verify(lc_proof_statement_VRG);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to verify heg proof!");
        return false;
    }
    vector<CurvePoint> points;
    points.push_back(bc_message_arr_[pos].V_);
    points.push_back(bc_message_arr_[pos].A_);
    BN commitment = safeheron::commitment::CreateComWithBlind(points, bc_message_arr_[pos].blind_factor_);
    ok = (commitment == ctx->remote_parties_[pos].commitment_VA_);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to verify commitment(V, A, B)!");
        return false;
    }

    ctx->remote_parties_[pos].V_ = bc_message_arr_[pos].V_;
    ctx->remote_parties_[pos].A_ = bc_message_arr_[pos].A_;

    return true;
}

bool Round6::ComputeVerify() {
    bool ok = true;
    // Validate child private key share
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    // V = g^{-m} y^{-r} Prod{V_i}
    CurvePoint V = ctx->local_party_.V_;
    for(size_t i = 0; i < ctx->remote_parties_.size(); ++i){
        V += ctx->remote_parties_[i].V_;
    }
    V += curv->g * ctx->m_.Neg();
    V += sign_key.X_ * ctx->r_.Neg();
    ctx->V_ = V;

    // Ui and Ti
    CurvePoint U = V * ctx->local_party_.rho_;
    CurvePoint T = ctx->local_party_.A_;
    for(size_t i = 0; i < ctx->remote_parties_.size(); ++i){
        T += ctx->remote_parties_[i].A_;
    }
    T = T * ctx->local_party_.l_;
    ctx->local_party_.U_ = U;
    ctx->local_party_.T_ = T;

    vector<CurvePoint> points;
    points.push_back(ctx->local_party_.U_);
    points.push_back(ctx->local_party_.T_);
    ctx->local_party_.blind_factor_3_ = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.commitment_UT_ = safeheron::commitment::CreateComWithBlind(points, ctx->local_party_.blind_factor_3_);

    return true;
}

bool Round6::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                         std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        out_des_arr.push_back(sign_key.remote_parties_[i].party_id_);
    }

    Round6BCMessage bc_message;
    bc_message.commitment_ = ctx->local_party_.commitment_UT_;
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
