#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-sss/vsss.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_key_gen/round3.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_key_gen/context.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::sss::Polynomial;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;

static BN POW2_256 = BN(1) << 256;

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace minimal_key_gen {

void Round3::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int j = 0; j < ctx->get_total_parties() - 1; ++j) {
        bc_message_arr_.emplace_back();
    }
}

bool Round3::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    MinimalSignKey &minimal_sign_key = ctx->minimal_sign_key_;

    int pos = minimal_sign_key.get_remote_party_pos(party_id);
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
    MinimalSignKey &minimal_sign_key = ctx->minimal_sign_key_;
    bool ok = true;

    int pos = minimal_sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    ok = compare_bytes(ctx->sid_, bc_message_arr_[pos].sid_) == 0;
    if(!ok){
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in compare_bytes(ctx->ssid_, bc_message_arr_[pos].ssid_) == 0");
        return false;
    }

    ok = (bc_message_arr_[pos].psi_.A_ == ctx->remote_parties_[pos].A_);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in (message_arr_[pos].psi_.A_ == ctx->remote_parties_[pos].A_)");
        return false;
    }
    bc_message_arr_[pos].psi_.SetSalt(ctx->remote_parties_[pos].sid_index_rid_);
    ok = bc_message_arr_[pos].psi_.Verify(ctx->remote_parties_[pos].X_);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Receive a differentr g^sign_key_share, or failed to verify schnorr proof of sign_key share!");
        return false;
    }

    ok = (bc_message_arr_[pos].phi_.A_ == ctx->remote_parties_[pos].B_);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in (message_arr_[pos].phi_.A_ == ctx->remote_parties_[pos].B_)");
        return false;
    }
    bc_message_arr_[pos].phi_.SetSalt(ctx->remote_parties_[pos].sid_index_rid_);
    ok = bc_message_arr_[pos].phi_.Verify(minimal_sign_key.remote_parties_[pos].X_);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Receive a differentr g^sign_key_share, or failed to verify schnorr proof of sign_key share!");
        return false;
    }

    return true;
}

bool Round3::ComputeVerify() {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    MinimalSignKey &minimal_sign_key = ctx->minimal_sign_key_;
    const curve::Curve *curv = ctx->GetCurrentCurve();

    CurvePoint X = ctx->local_party_.X_;
    for (const auto & remote_party : ctx->remote_parties_) {
        X += remote_party.X_;
    }

    vector<BN> share_index_arr;
    for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
        share_index_arr.push_back(minimal_sign_key.remote_parties_[j].index_);
    }
    share_index_arr.push_back(minimal_sign_key.local_party_.index_);

    vector<BN> l_arr;
    Polynomial::GetLArray(l_arr, BN::ZERO, share_index_arr, curv->n);

    CurvePoint X_star = minimal_sign_key.local_party_.X_ * l_arr.back();
    for (size_t j = 0; j < minimal_sign_key.remote_parties_.size(); ++j) {
        X_star += minimal_sign_key.remote_parties_[j].X_ * l_arr[j];
    }

    ok = X == X_star;
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "X == X_star");
        return false;
    }

    minimal_sign_key.X_ = X;
    minimal_sign_key.rid_ = ctx->rid_;

    return true;
}

bool Round3::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                             std::vector<std::string> &out_des_arr) const {
    // For final round, do nothing.
    return true;
}

}
}
}
}
