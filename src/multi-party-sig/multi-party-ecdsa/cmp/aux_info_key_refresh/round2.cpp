#include <cstdio>
#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-hash/safe_hash256.h"
#include "crypto-suites/crypto-encode/hex.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/aux_info_key_refresh/context.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/aux_info_key_refresh/round2.h"

using std::string;
using safeheron::hash::CSafeHash256;
using safeheron::sss::Polynomial;
using safeheron::bignum::BN;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::zkp::pail::PailProof;

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace aux_info_key_refresh {

void Round2::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        bc_message_arr_.emplace_back();
    }
}

bool Round2::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
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

bool Round2::ReceiveVerify(const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;
    bool ok = true;
    const Curve * curv = ctx->GetCurrentCurve();

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    ok = compare_bytes(ctx->ssid_, bc_message_arr_[pos].ssid_) == 0;
    if(!ok){
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in compare_bytes(ctx->ssid_, bc_message_arr_[pos].ssid_) == 0");
        return false;
    }

    // check rho
    ok = (bc_message_arr_[pos].rho_.size() == CSafeHash256::OUTPUT_SIZE);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__,
                           "(bc_message_arr_[pos].rho_.size() == CSHA256::OUTPUT_SIZE)");
        return false;
    }

    // Verify DLN Proof (N, s, t)
    bc_message_arr_[pos].psi_tilde_.SetSalt(ctx->remote_parties_[pos].ssid_index_);
    ok = bc_message_arr_[pos].psi_tilde_.Verify(bc_message_arr_[pos].N_, bc_message_arr_[pos].s_, bc_message_arr_[pos].t_);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "ok = message_arr_[pos].psi_tilde_.Verify(message_arr_[pos].N_, message_arr_[pos].s_, message_arr_[pos].t_);");
        return false;
    }

    // Verify V = H( ssid || i || X_arr || A_arr || Y || B || N || s || t || psi_tilde || rho || flag_update_minimal_key || u )
    uint8_t digest[CSafeHash256::OUTPUT_SIZE];
    CSafeHash256 sha256;
    string buf;
    // sid
    sha256.Write(reinterpret_cast<const unsigned char *>(bc_message_arr_[pos].ssid_.c_str()), bc_message_arr_[pos].ssid_.size());
    // index
    bc_message_arr_[pos].index_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // X
    for(const auto &item: bc_message_arr_[pos].map_party_id_X_){
        item.second.EncodeFull(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    }
    // c
    for(size_t i = 0; i < bc_message_arr_[pos].c_.size(); ++i){
        bc_message_arr_[pos].c_[i].EncodeFull(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    }
    // A
    for(const auto &item: bc_message_arr_[pos].map_party_id_A_){
        item.second.EncodeFull(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    }
    // Y
    bc_message_arr_[pos].Y_.EncodeFull(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // B
    bc_message_arr_[pos].B_.EncodeFull(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // N
    bc_message_arr_[pos].N_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // s
    bc_message_arr_[pos].s_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // t
    bc_message_arr_[pos].t_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // psi_tilde
    for(size_t i = 0; i < ctx->local_party_.psi_tilde_.dln_proof_1_.alpha_arr_.size(); ++i){
        bc_message_arr_[pos].psi_tilde_.dln_proof_1_.alpha_arr_[i].ToBytesBE(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
        bc_message_arr_[pos].psi_tilde_.dln_proof_1_.t_arr_[i].ToBytesBE(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    }
    for(size_t i = 0; i < ctx->local_party_.psi_tilde_.dln_proof_2_.alpha_arr_.size(); ++i){
        bc_message_arr_[pos].psi_tilde_.dln_proof_2_.alpha_arr_[i].ToBytesBE(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
        bc_message_arr_[pos].psi_tilde_.dln_proof_2_.t_arr_[i].ToBytesBE(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    }
    // rho
    sha256.Write(reinterpret_cast<const unsigned char *>(bc_message_arr_[pos].rho_.c_str()), bc_message_arr_[pos].rho_.size());
    //flag_update_minimal_key
    if (ctx->flag_update_minimal_key_) {
        std::string bool_str = "true";
        sha256.Write(reinterpret_cast<const unsigned char *>(bool_str.c_str()), bool_str.size());
    } else {
        std::string bool_str = "false";
        sha256.Write(reinterpret_cast<const unsigned char *>(bool_str.c_str()), bool_str.size());
    }
    // u
    sha256.Write(reinterpret_cast<const unsigned char *>(bc_message_arr_[pos].u_.c_str()), bc_message_arr_[pos].u_.size());
    sha256.Finalize(digest);

    // check Commitment
    ok = (ctx->remote_parties_[pos].V_.size() == CSafeHash256::OUTPUT_SIZE) && (0 == memcmp(ctx->remote_parties_[pos].V_.c_str(), digest, CSafeHash256::OUTPUT_SIZE));
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "ok = (ctx->local_party_.V_.size() == CSHA256::OUTPUT_SIZE) && (0 == memcmp(ctx->local_party_.V_.c_str(), digest, CSHA256::OUTPUT_SIZE))!");
        return false;
    }

    std::vector<BN> share_index_arr;
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        share_index_arr.push_back(sign_key.remote_parties_[i].index_);
    }
    share_index_arr.push_back(sign_key.local_party_.index_);

    std::vector<BN> l_arr;
    Polynomial::GetLArray(l_arr, BN::ZERO, share_index_arr, curv->n);

    CurvePoint ExpectedX = bc_message_arr_[pos].map_party_id_X_.at(sign_key.local_party_.party_id_) * l_arr.back();
    for(size_t i = 0; i < sign_key.remote_parties_.size(); ++i) {
        ExpectedX += bc_message_arr_[pos].map_party_id_X_.at(sign_key.remote_parties_[i].party_id_) * l_arr[i];
    }
    ok = (ExpectedX == curv->g * BN(0));
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "ok = (ExpectedX == curv->g * BN(0)");
        return false;
    }

    // Save( X, A, Y, B, N, s, t, rho, u)
    ctx->remote_parties_[pos].map_party_id_X_ = bc_message_arr_[pos].map_party_id_X_;
    ctx->remote_parties_[pos].map_remote_party_id_A_ = bc_message_arr_[pos].map_party_id_A_;
    ctx->remote_parties_[pos].c_ = bc_message_arr_[pos].c_;
    ctx->remote_parties_[pos].B_ = bc_message_arr_[pos].B_;
    ctx->remote_parties_[pos].rho_ = bc_message_arr_[pos].rho_;
    ctx->remote_parties_[pos].u_ = bc_message_arr_[pos].u_;

    sign_key.remote_parties_[pos].Y_ = bc_message_arr_[pos].Y_;
    sign_key.remote_parties_[pos].N_ = bc_message_arr_[pos].N_;
    sign_key.remote_parties_[pos].s_ = bc_message_arr_[pos].s_;
    sign_key.remote_parties_[pos].t_ = bc_message_arr_[pos].t_;

    return true;
}

bool Round2::ComputeVerify() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;
    bool ok = true;
    const curve::Curve *curv = ctx->GetCurrentCurve();

    string rho = ctx->local_party_.rho_;
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        for (size_t k = 0; k < CSafeHash256::OUTPUT_SIZE; ++k) {
            rho[k] ^= ctx->remote_parties_[i].rho_[k];
        }
    }
    ctx->rho_ = rho;

    ctx->ComputeSSID_Rho_Index();

    // Paillier Blum Modulus Proof
    ctx->local_party_.psi_.SetSalt(ctx->local_party_.sid_rho_index_);
    ctx->local_party_.psi_.Prove(sign_key.local_party_.N_,
                                 sign_key.local_party_.p_,
                                 sign_key.local_party_.q_);

    // No small factor proof
    for(size_t j = 0; j < sign_key.remote_parties_.size(); ++j){
        safeheron::zkp::no_small_factor_proof::NoSmallFactorSetUp set_up(sign_key.remote_parties_[j].N_,
                                                                         sign_key.remote_parties_[j].s_,
                                                                         sign_key.remote_parties_[j].t_);
        safeheron::zkp::no_small_factor_proof::NoSmallFactorStatement statement(sign_key.local_party_.N_, 256, 512);
        safeheron::zkp::no_small_factor_proof::NoSmallFactorWitness witness(sign_key.local_party_.p_, sign_key.local_party_.q_);
        ctx->remote_parties_[j].phi_.SetSalt(ctx->local_party_.sid_rho_index_);
        ctx->remote_parties_[j].phi_.Prove(set_up, statement, witness);
    }

    // C = Enc(x) for every remote party
    // DlogProof for x
    for(size_t j = 0; j < sign_key.remote_parties_.size(); ++j){
        safeheron::pail::PailPubKey pail_pub(sign_key.remote_parties_[j].N_, sign_key.remote_parties_[j].N_ + 1);
        BN &tau = ctx->local_party_.map_remote_party_id_tau_[sign_key.remote_parties_[j].party_id_];
        BN &x = ctx->local_party_.map_party_id_x_[sign_key.remote_parties_[j].party_id_];

        ctx->remote_parties_[j].C_ = pail_pub.Encrypt(x);
        ctx->remote_parties_[j].psi_.SetSalt(ctx->local_party_.sid_rho_index_);
        ctx->remote_parties_[j].psi_.ProveWithREx(x, tau, ctx->GetCurrentCurveType());
    }

    // Schnorr Proof
    ctx->local_party_.pi_.SetSalt(ctx->local_party_.sid_rho_index_);
    ctx->local_party_.pi_.ProveWithREx(ctx->local_party_.y_, ctx->local_party_.tau_, ctx->GetCurrentCurveType());

    return true;
}

bool Round2::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                             std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
        out_des_arr.push_back(sign_key.remote_parties_[j].party_id_);
    }

    for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
        Round2P2PMessage p2p_message;
        p2p_message.ssid_ = ctx->ssid_;
        p2p_message.index_ = sign_key.local_party_.index_;
        p2p_message.psi_ = ctx->local_party_.psi_;
        p2p_message.phi_ij_ = ctx->remote_parties_[j].phi_;
        p2p_message.pi_ = ctx->local_party_.pi_;
        p2p_message.C_ = ctx->remote_parties_[j].C_;
        p2p_message.psi_ij_ = ctx->remote_parties_[j].psi_;
        string base64;
        bool ok = p2p_message.ToBase64(base64);
        if (!ok) {
            ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to encode to base64!");
            return false;
        }
        out_p2p_msg_arr.push_back(base64);
    }

    return true;
}

}
}
}
}
