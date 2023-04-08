
#include "round2.h"
#include <cstdio>
#include "context.h"
#include "crypto-commitment/commitment.h"
#include "crypto-hash/sha256.h"
#include "crypto-encode/hex.h"
#include "crypto-sss/vsss.h"

using std::string;
using std::vector;
using std::map;
using safeheron::hash::CSHA256;
using safeheron::bignum::BN;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::zkp::pail::PailProof;

namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {
namespace minimal_key_gen {

void Round2::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        bc_message_arr_.emplace_back();
        p2p_message_arr_.emplace_back();
    }
}

bool Round2::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
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

    ok = p2p_message_arr_[pos].FromBase64(p2p_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64!");
        return false;
    }

    return true;
}

bool Round2::ReceiveVerify(const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    MinimalSignKey &minimal_sign_key = ctx->minimal_sign_key_;
    bool ok = true;
    const Curve *curv = ctx->GetCurrentCurve();

    int pos = minimal_sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    uint8_t digest[CSHA256::OUTPUT_SIZE];
    CSHA256 sha256;
    string buf;
    // sid
    sha256.Write(reinterpret_cast<const unsigned char *>(bc_message_arr_[pos].sid_.c_str()),
                 bc_message_arr_[pos].sid_.size());
    // index
    bc_message_arr_[pos].index_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // rid
    sha256.Write(reinterpret_cast<const unsigned char *>(bc_message_arr_[pos].rid_.c_str()),
                 bc_message_arr_[pos].rid_.size());
    // X
    bc_message_arr_[pos].X_.x().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    bc_message_arr_[pos].X_.y().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // A
    bc_message_arr_[pos].A_.x().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    bc_message_arr_[pos].A_.y().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // B
    bc_message_arr_[pos].B_.x().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    bc_message_arr_[pos].B_.y().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // c
    for (size_t i = 0; i < bc_message_arr_[pos].c_.size(); ++i) {
        bc_message_arr_[pos].c_[i].x().ToBytesBE(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
        bc_message_arr_[pos].c_[i].y().ToBytesBE(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    }
    // map_id_X
    map<string, CurvePoint>::iterator iter;
    for (iter = bc_message_arr_[pos].map_party_id_X_.begin(); iter != bc_message_arr_[pos].map_party_id_X_.end(); ++iter) {
        iter->second.x().ToBytesBE(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
        iter->second.y().ToBytesBE(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    }
    // u
    sha256.Write(reinterpret_cast<const unsigned char *>(bc_message_arr_[pos].u_.c_str()), bc_message_arr_[pos].u_.size());
    sha256.Finalize(digest);

    // check Commitment
    ok = (ctx->remote_parties_[pos].V_.size() == CSHA256::OUTPUT_SIZE) &&
         (0 == memcmp(ctx->remote_parties_[pos].V_.c_str(), digest, CSHA256::OUTPUT_SIZE));
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__,
                           "ok = (ctx->local_party_.V_.size() == CSHA256::OUTPUT_SIZE) && (0 == memcmp(ctx->local_party_.V_.c_str(), digest, CSHA256::OUTPUT_SIZE))!");
        return false;
    }

    // check rid
    ok = (bc_message_arr_[pos].rid_.size() == CSHA256::OUTPUT_SIZE);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__,
                           "(bc_message_arr_[pos].rid_.size() == CSHA256::OUTPUT_SIZE)");
        return false;
    }

    // check x_ij
    ok = safeheron::sss::vsss::VerifyShare(bc_message_arr_[pos].c_,
                                                     minimal_sign_key.local_party_.index_,
                                                     p2p_message_arr_[pos].x_ij_,
                                                     curv->g,
                                                     curv->n);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__,
                           "ok = safeheron::sss::vsss::VerifyShare(message_arr_[pos].F_arr_, minimal_sign_key.remote_parties_[pos].index_, message_arr_[pos].x_ij_)");
        return false;
    }

    iter = bc_message_arr_[pos].map_party_id_X_.find(minimal_sign_key.local_party_.party_id_);
    if(iter == ctx->remote_parties_[pos].map_party_id_X_.end()){
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__,
                           "invalid party_id : iter = ctx->local_party_.map_party_id_X_.find(minimal_sign_key.remote_parties_[pos].party_id_)");
        return false;
    }

    ok = iter->second == curv->g * p2p_message_arr_[pos].x_ij_;
    if(!ok){
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__,
                           "ok = iter->second == curv->g * message_arr_[pos].x_ij_");
        return false;
    }

    // save index
    minimal_sign_key.remote_parties_[pos].index_ = bc_message_arr_[pos].index_;
    // save rid
    ctx->remote_parties_[pos].rid_ = bc_message_arr_[pos].rid_;
    // save X
    ctx->remote_parties_[pos].X_ = bc_message_arr_[pos].X_;
    // save A
    ctx->remote_parties_[pos].A_ = bc_message_arr_[pos].A_;
    // save B
    ctx->remote_parties_[pos].B_ = bc_message_arr_[pos].B_;
    // save u
    ctx->remote_parties_[pos].u_ = bc_message_arr_[pos].u_;
    // save F_arr
    ctx->remote_parties_[pos].c_ = bc_message_arr_[pos].c_;
    // save map_id_X
    ctx->remote_parties_[pos].map_party_id_X_ = bc_message_arr_[pos].map_party_id_X_;
    // save x_ij
    ctx->remote_parties_[pos].x_ij_ = p2p_message_arr_[pos].x_ij_;

    return true;
}

bool Round2::ComputeVerify() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    MinimalSignKey &minimal_sign_key = ctx->minimal_sign_key_;
    bool ok = true;
    const curve::Curve *curv = ctx->GetCurrentCurve();

    BN x = ctx->local_party_.map_party_id_x_[minimal_sign_key.local_party_.party_id_];
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        x = (x + ctx->remote_parties_[i].x_ij_) % curv->n;
    }
    minimal_sign_key.local_party_.x_ = x;

    // set X^*
    CurvePoint X_star = ctx->local_party_.map_party_id_X_[minimal_sign_key.local_party_.party_id_];
    for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
        X_star += ctx->remote_parties_[j].map_party_id_X_[minimal_sign_key.local_party_.party_id_];
    }
    minimal_sign_key.local_party_.X_ = X_star;
    map<string, CurvePoint>::iterator iter;
    for (size_t k = 0; k < ctx->remote_parties_.size(); ++k) {
        X_star = ctx->local_party_.map_party_id_X_[minimal_sign_key.remote_parties_[k].party_id_];
        for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
            X_star += ctx->remote_parties_[j].map_party_id_X_[minimal_sign_key.remote_parties_[k].party_id_];
        }
        minimal_sign_key.remote_parties_[k].X_ = X_star;
    }

    string rid = ctx->local_party_.rid_;
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        for (size_t k = 0; k < CSHA256::OUTPUT_SIZE; ++k) {
            rid[k] ^= ctx->remote_parties_[i].rid_[k];
        }
    }
    ctx->rid_ = rid;

    // Schnorr Non-interactive Zero-Knowledge Proof
    ctx->local_party_.psi_.SetSalt(ctx->rid_);
    ctx->local_party_.psi_.ProveWithREx(ctx->local_party_.x_, ctx->local_party_.tau_, ctx->GetCurrentCurveType());

    ctx->local_party_.phi_.SetSalt(ctx->rid_);
    ctx->local_party_.phi_.ProveWithREx(minimal_sign_key.local_party_.x_, ctx->local_party_.r_, ctx->GetCurrentCurveType());

    return true;
}

bool Round2::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                             std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    MinimalSignKey &minimal_sign_key = ctx->minimal_sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        out_des_arr.push_back(minimal_sign_key.remote_parties_[i].party_id_);
    }

    Round2BCMessage bc_message;
    bc_message.sid_ = ctx->ssid_;
    bc_message.index_ = minimal_sign_key.local_party_.index_;
    bc_message.psi_ = ctx->local_party_.psi_;
    bc_message.phi_ = ctx->local_party_.phi_;
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
