#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "multi-party-sig/multi-party-ecdsa/gg20/sign/round5.h"
#include "multi-party-sig/multi-party-ecdsa/gg20/sign/context.h"

using std::string;
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
using safeheron::zkp::heg::HEGStatement_V3;
using safeheron::zkp::heg::HEGProof_V3;
using safeheron::zkp::heg::HEGWitness_V3;

static BN POW2_256 = BN(1) << 256;

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg20{
namespace sign{

void Round5::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        bc_message_arr_.emplace_back();
        p2p_message_arr_.emplace_back();
    }
}

bool Round5::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
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

    ok = p2p_message_arr_[pos].FromBase64(p2p_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64!");
        return false;
    }

    return true;
}

bool Round5::ReceiveVerify(const std::string &party_id) {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    PailEncGroupEleRangeSetUp setup(sign_key.local_party_.N_tilde_,
                                     sign_key.local_party_.h1_,
                                     sign_key.local_party_.h2_);
    PailEncGroupEleRangeStatement statement(ctx->remote_parties_[pos].receive_message_a_,
                                            sign_key.remote_parties_[pos].pail_pub_.n(),
                                            sign_key.remote_parties_[pos].pail_pub_.n_sqr(),
                                            curv->n,
                                            bc_message_arr_[pos].R_,
                                            ctx->R_,
                                            256, 512);
    ok = p2p_message_arr_[pos].pail_enc_group_ele_range_proof_.Verify(setup, statement);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to verify the 'pail_enc_group_ele_range_proof_'!");
        return false;
    }

    ctx->remote_parties_[pos].Ri_ = bc_message_arr_[pos].R_;

    return true;
}

bool Round5::ComputeVerify() {
    bool ok = true;
    // Validate child private key share
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    CurvePoint sum = ctx->local_party_.Ri_;
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        sum += ctx->remote_parties_[i].Ri_;
    }
    ok = sum == curv->g;
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed: g != Prod(Ri)!");
        return false;
    }

    ctx->local_party_.S_ = ctx->R_ * ctx->local_party_.sigma_;

    HEGStatement_V3 statement(ctx->local_party_.T_, curv->g, ctx->local_party_.H_, ctx->local_party_.S_, ctx->R_, curv->n);
    HEGWitness_V3 witness(ctx->local_party_.sigma_, ctx->local_party_.l_);
    ctx->local_party_.heg_proof_.Prove(statement, witness);

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
    bc_message.S_ = ctx->local_party_.S_;
    bc_message.heg_proof_ = ctx->local_party_.heg_proof_;
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
