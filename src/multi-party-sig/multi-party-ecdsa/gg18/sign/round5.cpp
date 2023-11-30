#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign/round5.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign/context.h"

using std::string;
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

void Round5::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        bc_message_arr_.emplace_back();
    }
}

bool Round5::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
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

bool Round5::ReceiveVerify(const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }
    ctx->remote_parties_[pos].commitment_VA_ = bc_message_arr_[pos].commitment_;

    return true;
}

bool Round5::ComputeVerify() {
    bool ok = true;
    // Validate child private key share
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    // Witness
    ctx->local_party_.lc_witness_VRG_.s_ = ctx->local_party_.si_;
    ctx->local_party_.lc_witness_VRG_.l_ = ctx->local_party_.l_;
    // Statement
    ctx->local_party_.lc_statement_VRG_.V_ = ctx->local_party_.V_;
    ctx->local_party_.lc_statement_VRG_.R_ = ctx->R_;
    ctx->local_party_.lc_statement_VRG_.G_ = curv->g;
    ctx->local_party_.lc_statement_VRG_.ord_ = curv->n;
    // Generate VRG proof
    ctx->local_party_.lc_proof_VRG_.Prove(ctx->local_party_.lc_statement_VRG_,
                                            ctx->local_party_.lc_witness_VRG_);

    // Schnorr Proof ( A_rho =  g^rho)
    ctx->local_party_.dlog_proof_rho_.ProveEx(ctx->local_party_.rho_, sign_key.X_.GetCurveType());

    return true;
}

bool Round5::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                         std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        out_des_arr.push_back(sign_key.remote_parties_[i].party_id_);
    }

    Round5BCMessage bc_message;
    bc_message.V_ = ctx->local_party_.V_;
    bc_message.A_ = ctx->local_party_.A_;
    bc_message.blind_factor_ = ctx->local_party_.blind_factor_2_;
    bc_message.lc_proof_VRG_ = ctx->local_party_.lc_proof_VRG_;
    bc_message.dlog_proof_rho_ = ctx->local_party_.dlog_proof_rho_;
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
