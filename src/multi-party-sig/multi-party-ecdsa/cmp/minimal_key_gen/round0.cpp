
#include "crypto-suites/crypto-hash/safe_hash256.h"
#include "crypto-suites/crypto-encode/hex.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_key_gen/round0.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_key_gen/context.h"

using std::string;
using std::vector;
using std::map;
using safeheron::hash::CSafeHash256;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace minimal_key_gen {

bool Round0::ComputeVerify() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    MinimalSignKey &minimal_sign_key = ctx->minimal_sign_key_;
    const curve::Curve* curv = ctx->GetCurrentCurve();

    // Sample rid_i in {0,1}^256
    uint8_t buf32[32];
    safeheron::rand::RandomBytes(buf32, sizeof(buf32));
    ctx->local_party_.rid_.assign(reinterpret_cast<const char *>(buf32), sizeof(buf32));

    // Sample \tau_i in Zq
    // set A_i = g * \tau_i
    ctx->local_party_.tau_ = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.A_ = curv->g * ctx->local_party_.tau_;

    // Sample r_i in Zq
    // set B_i = g * r_i
    ctx->local_party_.r_ = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.B_ = curv->g * ctx->local_party_.r_;

    // Feldman's VSSS
    vector<safeheron::sss::Point> share_points;
    vector<safeheron::curve::CurvePoint> vs;
    vector<BN> share_index_arr;
    vector<BN> rand_polynomial_coe_arr_;
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        share_index_arr.push_back(minimal_sign_key.remote_parties_[i].index_);
    }
    share_index_arr.push_back(minimal_sign_key.local_party_.index_);

    // check if index == 0
    // if index == 0, return false
    bool ok = safeheron::multi_party_ecdsa::cmp::CheckIndexArr(share_index_arr, curv->n);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to check index!");
        return false;
    }

    // Sample coefficient of polynomial
    // g(x) = s + f_1 * x + .... + f_{t-1} * x^{t-1} mod q
    for(size_t j = 1; j < minimal_sign_key.threshold_; ++j){
        BN num = safeheron::rand::RandomBNLt(curv->n);
        ctx->local_party_.f_arr_.push_back(num);
    }
    // Secret sharing scheme with Feldeman Commitment
    // x, {f_i}, threshold => {c_i}, {x_ij}
    safeheron::sss::vsss::MakeSharesWithCommitsAndCoes(share_points,
                                                                 ctx->local_party_.c_,
                                                                 ctx->local_party_.x_,
                                                                 minimal_sign_key.threshold_,
                                                                 share_index_arr,
                                                                 ctx->local_party_.f_arr_,
                                                                 curv->n,
                                                                 curv->g);
    ctx->local_party_.map_party_id_x_[minimal_sign_key.local_party_.party_id_] = share_points[share_index_arr.size() - 1].y;
    ctx->local_party_.map_party_id_X_[minimal_sign_key.local_party_.party_id_] = curv->g * share_points[share_index_arr.size() - 1].y;
    for(size_t j = 0; j < minimal_sign_key.n_parties_ - 1; ++j){
        ctx->local_party_.map_party_id_x_[minimal_sign_key.remote_parties_[j].party_id_] = share_points[j].y;
        ctx->local_party_.map_party_id_X_[minimal_sign_key.remote_parties_[j].party_id_] = curv->g * share_points[j].y;
    }

    safeheron::rand::RandomBytes(buf32, sizeof(buf32));
    ctx->local_party_.u_.assign(reinterpret_cast<const char *>(buf32), sizeof(buf32));

    // V_i = H(sid, i, rid_i, X_i, A_i, B_i, {c_i = g * f_i}, {X_i} u_i)
    uint8_t digest[CSafeHash256::OUTPUT_SIZE];
    CSafeHash256 sha256;
    string buf;
    // sid
    sha256.Write(reinterpret_cast<const unsigned char *>(ctx->sid_.c_str()), ctx->sid_.size());
    // index
    minimal_sign_key.local_party_.index_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // rid
    sha256.Write(reinterpret_cast<const unsigned char *>(ctx->local_party_.rid_.c_str()), ctx->local_party_.rid_.size());
    // X
    ctx->local_party_.X_.EncodeFull(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // A
    ctx->local_party_.A_.EncodeFull(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // B
    ctx->local_party_.B_.EncodeFull(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // c
    for(size_t k = 0; k < ctx->local_party_.c_.size(); ++k){
        ctx->local_party_.c_[k].EncodeFull(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    }
    // map_id_X
    map<string, CurvePoint>::iterator iter;
    for(iter = ctx->local_party_.map_party_id_X_.begin(); iter != ctx->local_party_.map_party_id_X_.end(); ++iter){
        iter->second.EncodeFull(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    }
    // u
    sha256.Write(reinterpret_cast<const unsigned char *>(ctx->local_party_.u_.c_str()), ctx->local_party_.u_.size());
    sha256.Finalize(digest);

    ctx->local_party_.V_.assign((const char*)digest, sizeof(digest));

    return true;
}

bool Round0::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                             std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    MinimalSignKey &minimal_sign_key = ctx->minimal_sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
        out_des_arr.push_back(minimal_sign_key.remote_parties_[j].party_id_);
    }

    Round0BCMessage bc_message;
    bc_message.sid_ = ctx->sid_;
    bc_message.index_ = minimal_sign_key.local_party_.index_;
    bc_message.V_ = ctx->local_party_.V_;
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
