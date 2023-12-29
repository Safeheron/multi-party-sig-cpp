#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-sss/vsss.h"
#include "crypto-suites/crypto-hash/sha256.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_refresh/round0.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_refresh/context.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::hash::CSHA256;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::sss::Polynomial;

using safeheron::multi_party_ecdsa::gg18::SignKey;

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{
namespace key_refresh {


bool Round0::ComputeVerify() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;
    const Curve *curv = GetCurveParam(sign_key.X_.GetCurveType());

    // Compute w = x * lambda % q
    vector<BN> share_index_arr;
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        share_index_arr.push_back(sign_key.remote_parties_[i].index_);
    }
    share_index_arr.push_back(sign_key.local_party_.index_);
    Polynomial::GetLArray(ctx->local_party_.l_arr_, BN::ZERO, share_index_arr, curv->n);
    BN w = (sign_key.local_party_.x_ * ctx->local_party_.l_arr_[share_index_arr.size() - 1]) % curv->n;

    // VSSS
    for(size_t i = 1; i < sign_key.threshold_; ++i){
        BN num = safeheron::rand::RandomBNLt(curv->n);
        ctx->local_party_.rand_num_arr_for_polynomial_coe_.push_back(num);
    }
    safeheron::sss::vsss::MakeSharesWithCommitsAndCoes(ctx->local_party_.share_points_,
                                                ctx->local_party_.vs_,
                                                w,
                                                sign_key.threshold_,
                                                share_index_arr,
                                                ctx->local_party_.rand_num_arr_for_polynomial_coe_,
                                                curv->n,
                                                curv->g);

    // Generate (N_tilde, h1, h2)
    safeheron::zkp::dln_proof::GenerateN_tilde(sign_key.local_party_.N_tilde_,
                    sign_key.local_party_.h1_,
                    sign_key.local_party_.h2_,
                    sign_key.local_party_.p_,
                    sign_key.local_party_.q_,
                    sign_key.local_party_.alpha_,
                    sign_key.local_party_.beta_);

    // Generate Paillier's Key Pair
    CreateKeyPair2048(sign_key.local_party_.pail_priv_, sign_key.local_party_.pail_pub_);

    // Commitment(VS || N_tilde || h1 || h2 || pail_pub)
    char blind_factor_buf[256];
    safeheron::rand::RandomBytes((uint8_t *)blind_factor_buf, sizeof blind_factor_buf);
    ctx->local_party_.blind_factor_.assign(blind_factor_buf, sizeof blind_factor_buf);

    uint8_t digest[CSHA256::OUTPUT_SIZE];
    CSHA256 sha256;
    string buf;
    // VS Commitment
    for(size_t i = 0; i < ctx->local_party_.vs_.size(); ++i){
        ctx->local_party_.vs_[i].EncodeFull(buf);
        sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    }
    // N_tilde
    sign_key.local_party_.N_tilde_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // h1
    sign_key.local_party_.h1_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // h2
    sign_key.local_party_.h2_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    // pail_pub
    sign_key.local_party_.pail_pub_.n().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    sign_key.local_party_.pail_pub_.g().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    sha256.Write(reinterpret_cast<const unsigned char *>(ctx->local_party_.blind_factor_.c_str()), ctx->local_party_.blind_factor_.size());
    sha256.Finalize(digest);
    ctx->local_party_.V_.assign((const char*)digest, sizeof digest);

    // Last point belong to local party.
    ctx->local_party_.x_ij_ = ctx->local_party_.share_points_[share_index_arr.size() - 1].y;
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        ctx->remote_parties_[i].x_ij_ = ctx->local_party_.share_points_[i].y;
    }

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

    Round0BCMessage message;
    message.V_ = ctx->local_party_.V_;
    message.ToBase64(out_bc_msg);

    return true;
}


}
}
}
}
