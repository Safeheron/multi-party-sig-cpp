#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "multi-party-sig/multi-party-ecdsa/gg20/sign/round4.h"
#include "multi-party-sig/multi-party-ecdsa/gg20/sign/context.h"

using std::string;
using safeheron::bignum::BN;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::sss::Polynomial;
using safeheron::multi_party_ecdsa::gg18::SignKey;
using safeheron::zkp::pedersen_proof::PedersenStatement;
using safeheron::zkp::pedersen_proof::PedersenWitness;
using safeheron::zkp::pedersen_proof::PedersenProof;

static BN POW2_256 = BN(1) << 256;

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg20{
namespace sign{

void Round3::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        bc_message_arr_.emplace_back();
    }
}

bool Round3::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
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

bool Round3::ReceiveVerify(const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;
    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    int pos = sign_key.get_remote_party_pos(party_id);

    PedersenStatement pedersen_statement(curv->g, bc_message_arr_[pos].H_, bc_message_arr_[pos].T_);
    bool ok = bc_message_arr_[pos].pedersen_proof_.Verify(pedersen_statement);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to verify the 'pedersen_proof_'!");
        return false;
    }

    ctx->remote_parties_[pos].T_ = bc_message_arr_[pos].T_;
    ctx->remote_parties_[pos].H_ = bc_message_arr_[pos].H_;
    ctx->remote_parties_[pos].delta_ = bc_message_arr_[pos].delta_;

    return true;
}

bool Round3::ComputeVerify() {
    bool ok = true;
    // Validate child private key share
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    BN delta = ctx->local_party_.delta_;
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        delta = (delta +  ctx->remote_parties_[i].delta_) % curv->n;
    }
    ctx->delta_ = delta;

    return true;
}

bool Round3::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                             std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        out_des_arr.push_back(sign_key.remote_parties_[i].party_id_);
    }

    Round3BCMessage bc_message;
    bc_message.blind_factor_ = ctx->local_party_.com_Gamma_blinding_factor_;
    bc_message.Gamma_ = ctx->local_party_.Gamma_;
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
