#include "crypto-suites/crypto-hash/safe_hash256.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-encode/hex.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/aux_info_key_refresh/round0.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/aux_info_key_refresh/context.h"

using std::string;
using std::vector;
using safeheron::hash::CSafeHash256;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;

namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {
namespace aux_info_key_refresh {

bool Round0::ComputeVerify() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;
    const curve::Curve *curv = ctx->GetCurrentCurve();
    bool ok = true;

    if (!ctx->flag_prepare_pail_key_) {
        safeheron::zkp::dln_proof::GenerateN_tilde(sign_key.local_party_.N_,
                                                   sign_key.local_party_.s_,
                                                   sign_key.local_party_.t_,
                                                   ctx->local_party_.pp_,
                                                   ctx->local_party_.qq_,
                                                   sign_key.local_party_.alpha_,
                                                   sign_key.local_party_.beta_);
        sign_key.local_party_.p_ = ctx->local_party_.pp_ * 2 + 1;
        sign_key.local_party_.q_ = ctx->local_party_.qq_ * 2 + 1;
    }

    // Sample (B, tau)
    ctx->local_party_.tau_ = safeheron::rand::RandomBN(256);
    ctx->local_party_.B_ = curv->g * ctx->local_party_.tau_;

    // Sample (y, Y)
    ctx->local_party_.y_ = safeheron::rand::RandomBN(256);
    sign_key.local_party_.Y_ = curv->g * ctx->local_party_.y_;

    // Feldman's VSSS on 0
    vector<safeheron::sss::Point> share_points;
    vector<safeheron::curve::CurvePoint> vs;
    vector<BN> share_index_arr;
    vector<BN> rand_polynomial_coe_arr_;
    for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
        share_index_arr.push_back(sign_key.remote_parties_[j].index_);
    }
    share_index_arr.push_back(sign_key.local_party_.index_);
    for(size_t j = 1; j < sign_key.threshold_; ++j){
        BN num = safeheron::rand::RandomBNLt(curv->n);
        ctx->local_party_.f_arr_.push_back(num);
    }
    safeheron::sss::vsss::MakeSharesWithCommitsAndCoes(share_points,
                                                                 ctx->local_party_.c_,
                                                                 BN::ZERO,
                                                                 sign_key.threshold_,
                                                                 share_index_arr,
                                                                 ctx->local_party_.f_arr_,
                                                                 curv->n,
                                                                 curv->g);
    ctx->local_party_.map_party_id_x_[sign_key.local_party_.party_id_] = share_points[share_index_arr.size() - 1].y;
    ctx->local_party_.map_party_id_X_[sign_key.local_party_.party_id_] = curv->g * share_points[share_index_arr.size() - 1].y;
    for(size_t j = 0; j < sign_key.n_parties_ - 1; ++j){
        ctx->local_party_.map_party_id_x_[sign_key.remote_parties_[j].party_id_] = share_points[j].y;
        ctx->local_party_.map_party_id_X_[sign_key.remote_parties_[j].party_id_] = curv->g * share_points[j].y;
    }

    // Sample (tau_1, A_1), ... , (tau_n, A_n)
    for (const auto &remote_party: sign_key.remote_parties_) {
        BN tau = safeheron::rand::RandomBN(256);
        CurvePoint A = curv->g * tau;
        ctx->local_party_.map_remote_party_id_tau_[remote_party.party_id_] = tau;
        ctx->local_party_.map_remote_party_id_A_[remote_party.party_id_] = A;
    }

    // Sample (rho, u)
    uint8_t buf32[32];
    safeheron::rand::RandomBytes(buf32, sizeof buf32);
    ctx->local_party_.rho_.assign((char *)buf32, sizeof buf32);
    safeheron::rand::RandomBytes(buf32, sizeof buf32);
    ctx->local_party_.u_.assign((char *)buf32, sizeof buf32);

    ctx->local_party_.psi_tilde_.SetSalt(ctx->local_party_.sid_index_);
    ctx->local_party_.psi_tilde_.Prove(sign_key.local_party_.N_,
                                       sign_key.local_party_.s_,
                                       sign_key.local_party_.t_,
                                       ctx->local_party_.pp_,
                                       ctx->local_party_.qq_,
                                       sign_key.local_party_.alpha_,
                                       sign_key.local_party_.beta_);

    // V = H( ssid || i || X_arr || A_arr || Y || B || N || s || t || psi_tilde || rho || flag_update_minimal_key || u)
    uint8_t digest[CSafeHash256::OUTPUT_SIZE];
    CSafeHash256 sha256;
    string buf;
    // sid
    sha256.Write(reinterpret_cast<const unsigned char *>(ctx->ssid_.c_str()), ctx->ssid_.size());
    // index
    sign_key.local_party_.index_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // X
    for(const auto &item : ctx->local_party_.map_party_id_X_){
        item.second.EncodeFull(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    }
    // c
    for(size_t i = 0; i < ctx->local_party_.c_.size(); ++i){
        ctx->local_party_.c_[i].EncodeFull(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    }
    // A
    for(const auto &item: ctx->local_party_.map_remote_party_id_A_){
        item.second.EncodeFull(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    }
    // Y
    sign_key.local_party_.Y_.EncodeFull(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // B
    ctx->local_party_.B_.EncodeFull(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // N
    sign_key.local_party_.N_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // s
    sign_key.local_party_.s_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // t
    sign_key.local_party_.t_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // psi_tilde
    for(size_t i = 0; i < ctx->local_party_.psi_tilde_.dln_proof_1_.alpha_arr_.size(); ++i){
        ctx->local_party_.psi_tilde_.dln_proof_1_.alpha_arr_[i].ToBytesBE(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
        ctx->local_party_.psi_tilde_.dln_proof_1_.t_arr_[i].ToBytesBE(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    }
    for(size_t i = 0; i < ctx->local_party_.psi_tilde_.dln_proof_2_.alpha_arr_.size(); ++i){
        ctx->local_party_.psi_tilde_.dln_proof_2_.alpha_arr_[i].ToBytesBE(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
        ctx->local_party_.psi_tilde_.dln_proof_2_.t_arr_[i].ToBytesBE(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    }
    // rho
    sha256.Write(reinterpret_cast<const unsigned char *>(ctx->local_party_.rho_.c_str()), ctx->local_party_.rho_.size());
    //flag_update_minimal_key
    if (ctx->flag_update_minimal_key_) {
        std::string bool_str = "true";
        sha256.Write(reinterpret_cast<const unsigned char *>(bool_str.c_str()), bool_str.size());
    } else {
        std::string bool_str = "false";
        sha256.Write(reinterpret_cast<const unsigned char *>(bool_str.c_str()), bool_str.size());
    }
    // u
    sha256.Write(reinterpret_cast<const unsigned char *>(ctx->local_party_.u_.c_str()), ctx->local_party_.u_.size());
    sha256.Finalize(digest);

    ctx->local_party_.V_.assign((const char *) digest, sizeof(digest));

    return true;
}

bool Round0::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                             std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        out_des_arr.push_back(sign_key.remote_parties_[i].party_id_);
    }

    Round0BCMessage bc_message;
    bc_message.ssid_ = ctx->ssid_;
    bc_message.index_ = sign_key.local_party_.index_;
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
