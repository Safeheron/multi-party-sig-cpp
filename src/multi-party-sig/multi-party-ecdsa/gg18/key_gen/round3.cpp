
#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-sss/vsss.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_gen/round3.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_gen/context.h"

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
namespace gg18{
namespace key_gen {

void Round3::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        bc_message_arr_.emplace_back();
    }
}

bool Round3::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

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
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    ok = (bc_message_arr_[pos].pub_ == sign_key.X_);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Different public extend key!");
        return false;
    }

    ok = bc_message_arr_[pos].dlog_proof_x_.Verify();
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Receive a differentr g^sign_key_share, or failed to verify schnorr proof of sign_key share!");
        return false;
    }

    ok = bc_message_arr_[pos].pail_proof_.Verify(sign_key.remote_parties_[pos].pail_pub_.n());
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to verify paillier proof!");
        return false;
    }

    sign_key.remote_parties_[pos].g_x_ = bc_message_arr_[pos].dlog_proof_x_.pk_;

    return true;
}

bool Round3::ComputeVerify() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;
    const Curve * curv = GetCurveParam(ctx->curve_type_);

    vector<BN> share_index_arr;
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        share_index_arr.push_back(sign_key.remote_parties_[i].index_);
    }
    share_index_arr.push_back(sign_key.local_party_.index_);
    vector<BN> l_arr;
    Polynomial::GetLArray(l_arr, BN::ZERO, share_index_arr, curv->n);
    CurvePoint pub = sign_key.local_party_.g_x_ * l_arr[share_index_arr.size()-1];
    for (size_t i = 0; i < sign_key.remote_parties_.size(); ++i) {
        pub += sign_key.remote_parties_[i].g_x_ * l_arr[i];
    }

    if (pub != sign_key.X_) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to verify public key(ecdsa)!");
        return false;
    }
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
