#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-hash/sha256.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_refresh/round2.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_refresh/context.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::hash::CSHA256;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::sss::Polynomial;
using safeheron::multi_party_ecdsa::gg18::SignKey;

static BN POW2_256 = BN(1) << 256;

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{
namespace key_refresh {

void Round2::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        bc_message_arr_.emplace_back();
        p2p_message_arr_.emplace_back();
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
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64(bc)!");
        return false;
    }

    ok = p2p_message_arr_[pos].FromBase64(p2p_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64(p2p)!");
        return false;
    }


    return true;
}

bool Round2::ReceiveVerify(const std::string &party_id) {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;
    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    // Commitment(VS || N_tilde || h1 || h2 || pail_pub)
    uint8_t digest[CSHA256::OUTPUT_SIZE];
    CSHA256 sha256;
    string buf;
    // VS Commitment
    for(size_t i = 0; i < bc_message_arr_[pos].vs_.size(); ++i){
        bc_message_arr_[pos].vs_[i].EncodeFull(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    }
    // N_tilde
    bc_message_arr_[pos].N_tilde_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // h1
    bc_message_arr_[pos].h1_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // h2
    bc_message_arr_[pos].h2_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // pail_pub
    bc_message_arr_[pos].pail_pub_.n().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    bc_message_arr_[pos].pail_pub_.g().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    sha256.Write(reinterpret_cast<const unsigned char *>(bc_message_arr_[pos].blind_factor_.c_str()), bc_message_arr_[pos].blind_factor_.size());
    sha256.Finalize(digest);
    string V;
    V.assign((const char*)digest, sizeof digest);

    ok = V == ctx->remote_parties_[pos].V_;
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "V == ctx->remote_parties_[pos].V_");
        return false;
    }

    ok = safeheron::sss::vsss::VerifyShare(bc_message_arr_[pos].vs_, sign_key.threshold_, sign_key.local_party_.index_, p2p_message_arr_[pos].x_ij_, curv->g, curv->n);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "safeheron::sss::vsss_secp256k1::VerifyShare(message_arr_[pos].vs_, sign_key.local_party_.index_, message_arr_[pos].x_ij_)");
        return false;
    }

    sign_key.remote_parties_[pos].N_tilde_ = bc_message_arr_[pos].N_tilde_;
    sign_key.remote_parties_[pos].h1_ = bc_message_arr_[pos].h1_;
    sign_key.remote_parties_[pos].h2_ = bc_message_arr_[pos].h2_;
    ok = bc_message_arr_[pos].dln_proof_1_.Verify(bc_message_arr_[pos].N_tilde_,
                                                  bc_message_arr_[pos].h1_,
                                                  bc_message_arr_[pos].h2_);
    if(!ok){
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, string("Failed to verify DLN proof(dln_proof_1_) from party :") + sign_key.remote_parties_[pos].party_id_);
        return false;
    }
    ok = bc_message_arr_[pos].dln_proof_2_.Verify(bc_message_arr_[pos].N_tilde_,
                                                  bc_message_arr_[pos].h2_,
                                                  bc_message_arr_[pos].h1_);
    if(!ok){
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, string("Failed to verify DLN proof(dln_proof_2_) from party :") + sign_key.remote_parties_[pos].party_id_);
        return false;
    }

    sign_key.remote_parties_[pos].N_tilde_ = bc_message_arr_[pos].N_tilde_;
    sign_key.remote_parties_[pos].h1_ = bc_message_arr_[pos].h1_;
    sign_key.remote_parties_[pos].h2_ = bc_message_arr_[pos].h2_;
    sign_key.remote_parties_[pos].pail_pub_ = bc_message_arr_[pos].pail_pub_;
    ctx->remote_parties_[pos].x_ij_ = p2p_message_arr_[pos].x_ij_;

    return true;
}

bool Round2::ComputeVerify() {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());
    ctx->local_party_.new_x_ = ctx->local_party_.x_ij_;
    for (size_t i = 0; i < sign_key.remote_parties_.size(); ++i) {
        ctx->local_party_.new_x_ = (ctx->local_party_.new_x_ + ctx->remote_parties_[i].x_ij_) % curv->n;
    }
    ctx->local_party_.new_X_ = curv->g * ctx->local_party_.new_x_;
    ctx->local_party_.rand_num_for_schnorr_proof_ = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.dlog_proof_x_.ProveWithREx(ctx->local_party_.new_x_, ctx->local_party_.rand_num_for_schnorr_proof_, sign_key.X_.GetCurveType());

    // Paillier proof
    ctx->local_party_.pail_proof_.Prove(sign_key.local_party_.pail_pub_.n(),
                                        sign_key.local_party_.pail_priv_.p(),
                                        sign_key.local_party_.pail_priv_.q());


    // No small factor proof
    for(size_t i = 0; i < sign_key.remote_parties_.size(); ++i){
        safeheron::zkp::no_small_factor_proof::NoSmallFactorSetUp set_up(sign_key.remote_parties_[i].N_tilde_,
                                                                         sign_key.remote_parties_[i].h1_,
                                                                         sign_key.remote_parties_[i].h2_);
        safeheron::zkp::no_small_factor_proof::NoSmallFactorStatement statement(sign_key.local_party_.pail_pub_.n(), 256, 512);
        safeheron::zkp::no_small_factor_proof::NoSmallFactorWitness witness(sign_key.local_party_.pail_priv_.p(), sign_key.local_party_.pail_priv_.q());
        ctx->remote_parties_[i].nsf_proof_.Prove(set_up, statement, witness);
    }
    return true;
}

bool Round2::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                         std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        out_des_arr.push_back(sign_key.remote_parties_[i].party_id_);
    }

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        Round2P2PMessage message;
        message.dlog_proof_x_ = ctx->local_party_.dlog_proof_x_;
        message.pail_proof_ = ctx->local_party_.pail_proof_;
        message.nsf_proof_ = ctx->remote_parties_[i].nsf_proof_;
        string base64;
        bool ok = message.ToBase64(base64);
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
