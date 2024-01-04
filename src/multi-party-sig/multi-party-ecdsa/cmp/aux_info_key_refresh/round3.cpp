#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-sss/vsss.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/aux_info_key_refresh/round3.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/aux_info_key_refresh/context.h"

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
namespace aux_info_key_refresh {

void Round3::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int j = 0; j < ctx->get_total_parties() - 1; ++j) {
        p2p_message_arr_.emplace_back();
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

    bool ok = p2p_message_arr_[pos].FromBase64(p2p_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64!");
        return false;
    }

    return true;
}

bool Round3::ReceiveVerify(const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;
    const curve::Curve *curv = ctx->GetCurrentCurve();
    bool ok = true;

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    ok = compare_bytes(ctx->ssid_, p2p_message_arr_[pos].ssid_) == 0;
    if(!ok){
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in compare_bytes(ctx->ssid_, p2p_message_arr_[pos].ssid_) == 0");
        return false;
    }

    const BN &p = sign_key.local_party_.p_;
    const BN &q = sign_key.local_party_.q_;
    const BN N = p * q;
    const BN lambda = (p-1) * (q-1);
    const BN mu = lambda.InvM(N);
    safeheron::pail::PailPrivKey pail_priv(lambda, mu, N);
    BN x = pail_priv.Decrypt(p2p_message_arr_[pos].C_);
    x = x % q;
    CurvePoint X = curv->g * x;
    CurvePoint expected_X = ctx->remote_parties_[pos].map_party_id_X_[sign_key.local_party_.party_id_];
    ok = (X == expected_X);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "ok = (X == expected_X)");
        return false;
    }

    // check x_ij
    ok = safeheron::sss::vsss::VerifyShare(ctx->remote_parties_[pos].c_,
                                           sign_key.threshold_,
                                           sign_key.local_party_.index_,
                                           x,
                                           curv->g,
                                           curv->n);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__,
                           "Fail in 'safeheron::sss::vsss::VerifyShare(ctx->remote_parties_[pos].c_, sign_key.local_party_.index_, x, curv->g, curv->n)' ");
        return false;
    }

    p2p_message_arr_[pos].psi_.SetSalt(ctx->remote_parties_[pos].ssid_rho_index_);
    ok = p2p_message_arr_[pos].psi_.Verify(sign_key.remote_parties_[pos].N_);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "ok = message_arr_[pos].psi_.Verify(sign_key.remote_parties_[pos].N_)");
        return false;
    }

    safeheron::zkp::no_small_factor_proof::NoSmallFactorSetUp set_up(sign_key.local_party_.N_,
                                                                     sign_key.local_party_.s_,
                                                                     sign_key.local_party_.t_);
    safeheron::zkp::no_small_factor_proof::NoSmallFactorStatement statement(sign_key.remote_parties_[pos].N_, 256, 512);
    p2p_message_arr_[pos].phi_ij_.SetSalt(ctx->remote_parties_[pos].ssid_rho_index_);
    ok = p2p_message_arr_[pos].phi_ij_.Verify(set_up, statement);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "ok = message_arr_[pos].psi_.Verify(sign_key.remote_parties_[pos].N_)");
        return false;
    }

    p2p_message_arr_[pos].pi_.SetSalt(ctx->remote_parties_[pos].ssid_rho_index_);
    ok = p2p_message_arr_[pos].pi_.Verify(sign_key.remote_parties_[pos].Y_);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "ok = message_arr_[pos].pi_.Verify(expected_X)");
        return false;
    }
    ok = (p2p_message_arr_[pos].pi_.A_ == ctx->remote_parties_[pos].B_);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in (message_arr_[pos].psi_.A_ == ctx->remote_parties_[pos].A_)");
        return false;
    }


    p2p_message_arr_[pos].psi_ij_.SetSalt(ctx->remote_parties_[pos].ssid_rho_index_);
    ok = p2p_message_arr_[pos].psi_ij_.Verify(expected_X);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "ok = message_arr_[pos].psi_ij_.Verify(ctx->remote_parties_[pos].Y_)");
        return false;
    }
    CurvePoint expected_A = ctx->remote_parties_[pos].map_remote_party_id_A_[sign_key.local_party_.party_id_];
    ok = (p2p_message_arr_[pos].psi_ij_.A_ == expected_A);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in (message_arr_[pos].psi_ij_.A_ == expected_A)");
        return false;
    }

    ctx->remote_parties_[pos].x_ = x;

    return true;
}

bool Round3::ComputeVerify() {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;
    const curve::Curve *curv = ctx->GetCurrentCurve();

    if (ctx->flag_update_minimal_key_) {
        // Update private key share and public key share of local party
        const auto iter0 = ctx->local_party_.map_party_id_x_.find(sign_key.local_party_.party_id_);
        if (iter0 == ctx->local_party_.map_party_id_x_.end()) {
            ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__,
                               "iter0 == ctx->local_party_.map_remote_party_id_X_.end()");
            return false;
        }
        // Compute
        //  - x_i = x_i + \Sum_j{x_ij}
        //  - X_i = g * x_i
        BN x = sign_key.local_party_.x_;
        // add share(x_ij) from local party
        x = (x + iter0->second) % curv->n;
        for (const auto &remote_party: ctx->remote_parties_) {
            // add share(x_ij) from remote party
            x = (x + remote_party.x_) % curv->n;
        }
        sign_key.local_party_.x_ = x;
        sign_key.local_party_.X_ = curv->g * x;

        // Update public key share of remote parties
        // Compute X_i = X_i + \Sum_j{X_ij}
        for (size_t i = 0; i < sign_key.remote_parties_.size(); ++i) {
            const string &current_party_id = sign_key.remote_parties_[i].party_id_;
            CurvePoint X = sign_key.remote_parties_[i].X_;
            const auto iter1 = ctx->local_party_.map_party_id_X_.find(current_party_id);
            if (iter1 == ctx->local_party_.map_party_id_X_.end()) {
                ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__,
                                   "ctx->local_party_.map_remote_party_id_X_.find(current_party_id)");
                return false;
            }
            X += iter1->second;
            for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
                const auto &remote_party = ctx->remote_parties_[j];
                const auto iter2 = remote_party.map_party_id_X_.find(current_party_id);
                if (iter2 == remote_party.map_party_id_X_.end()) {
                    ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__,
                                       "remote_party.map_party_id_X_.find(current_party_id)");
                    return false;
                }
                X += iter2->second;
            }
            sign_key.remote_parties_[i].X_ = X;
        }
    }

    // Compute X = X_i + \Sum_j{X_j}
    vector<BN> share_index_arr;
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        share_index_arr.push_back(sign_key.remote_parties_[i].index_);
    }
    share_index_arr.push_back(sign_key.local_party_.index_);

    vector<BN> l_arr;
    Polynomial::GetLArray(l_arr, BN::ZERO, share_index_arr, curv->n);

    CurvePoint X = sign_key.local_party_.X_ * l_arr.back();
    for(size_t i = 0; i < sign_key.remote_parties_.size(); ++i) {
        X += sign_key.remote_parties_[i].X_ * l_arr[i];
    }

    // Verify X == sign_key.X, namely that public key keep the same.
    ok = X == sign_key.X_;
    if(!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "X == sign_key.X_");
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
