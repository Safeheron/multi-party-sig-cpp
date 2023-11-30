
#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_CONTEXT_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_CONTEXT_H

#include <vector>
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-bn/bn.h"
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/util.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign_key.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/t_party.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/round0.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/round1.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/round2.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/round3.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/round4.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace sign {

class Context : public safeheron::mpc_flow::mpc_parallel_v2::MPCContext {
public:
    /**
     * Default constructor
     */
    Context(int total_parties);

    /**
     * A copy constructor
     */
    Context(const Context &ctx);

    /**
     * A copy assignment operator
     */
    Context &operator=(const Context &ctx);

public:
    void BindAllRounds();

    static bool CreateContext(Context &ctx,
                              const std::string &sign_key_base64,
                              const safeheron::bignum::BN &m,
                              const std::string &ssid);

    const safeheron::curve::Curve * GetCurrentCurve() const{
        assert(sign_key_.X_.GetCurveType() != safeheron::curve::CurveType::INVALID_CURVE);
        const safeheron::curve::Curve* curv = safeheron::curve::GetCurveParam(sign_key_.X_.GetCurveType());;
        assert(curv);
        return curv;
    }

    safeheron::curve::CurveType GetCurrentCurveType() const{
        assert(sign_key_.X_.GetCurveType() != safeheron::curve::CurveType::INVALID_CURVE);
        return sign_key_.X_.GetCurveType();
    }

    bool IsValidPartyID(const std::string& party_id) const;
    std::string GetSSIDIndex(const std::string& party_id) const;
    const safeheron::pail::PailPubKey& GetPailPub(const std::string& party_id) const;
    const safeheron::bignum::BN& GetK(const std::string& party_id) const;
    const safeheron::bignum::BN& GetG(const std::string& party_id) const;
    const safeheron::bignum::BN& GetDelta(const std::string& party_id) const;
    const safeheron::bignum::BN& GetSigma(const std::string& party_id) const;
    const safeheron::curve::CurvePoint& GetGamma(const std::string& party_id) const;
    const safeheron::curve::CurvePoint& GetX(const std::string& party_id) const;
    const safeheron::bignum::BN& GetN(const std::string& party_id) const;
    const safeheron::bignum::BN& GetS(const std::string& party_id) const;
    const safeheron::bignum::BN& GetT(const std::string& party_id) const;

    void ExportDF(std::map<std::string, std::map<std::string,safeheron::bignum::BN>> &all_D,
                  std::map<std::string, std::map<std::string,safeheron::bignum::BN>> &all_F) const;

    void ExportD_hat_F_hat(std::map<std::string, std::map<std::string,safeheron::bignum::BN>> &all_D_hat,
                           std::map<std::string, std::map<std::string,safeheron::bignum::BN>> &all_F_hat) const;

    bool BuildProofInPreSignPhase(){ return round3_.BuildProof();}
    bool VerifyProof(std::map<std::string, ProofInPreSignPhase> &map_proof,
                     std::map<std::string, std::map<std::string, safeheron::bignum::BN>> &all_D,
                     std::map<std::string, std::map<std::string, safeheron::bignum::BN>> &all_F){ return round3_.VerifyProof(map_proof, all_D, all_F); }

    bool BuildProofInSignPhase(){ return round4_.BuildProof();}
    bool VerifyProof(std::map<std::string, ProofInSignPhase> &map_proof,
                     std::map<std::string, std::map<std::string, safeheron::bignum::BN>> &all_D_hat,
                     std::map<std::string, std::map<std::string, safeheron::bignum::BN>> &all_F_hat){ return round4_.VerifyProof(map_proof, all_D_hat, all_F_hat); }

    void Identify(const std::string &culprit,
                  int32_t round_index,
                  bool need_proof_in_pre_sign_phase = false,
                  bool need_proof_in_sign_phase = false){
        identify_culprit_ = culprit;
        identify_round_index_ = round_index;
        identify_need_proof_in_pre_sign_phase_ = need_proof_in_pre_sign_phase;
        identify_need_proof_in_sign_phase_ = need_proof_in_sign_phase;
    }

    std::string IdentifyCulprit() const { return identify_culprit_; };
    int32_t IdentifyRoundIndex() const { return identify_round_index_; };
    bool IdentifyNeedProofInPreSignPhase() const { return identify_need_proof_in_pre_sign_phase_; };
    bool IdentifyNeedProofInSignPhase() const { return identify_need_proof_in_sign_phase_; };

    void ComputeSSID(const std::string &sid);

    void ComputeSSID_Index();

public:
    std::string ssid_;
    safeheron::multi_party_ecdsa::cmp::SignKey sign_key_;
    safeheron::bignum::BN m_;

    LocalTParty local_party_;
    std::vector<RemoteTParty> remote_parties_;
    Round0 round0_;
    Round1 round1_;
    Round2 round2_;
    Round3 round3_;
    Round4 round4_;

    // temp data
    safeheron::bignum::BN delta_;
    safeheron::curve::CurvePoint Gamma_;
    safeheron::curve::CurvePoint R_;

    // signature
    safeheron::bignum::BN r_;
    safeheron::bignum::BN s_;
    uint32_t v_;

    // Proof in pre-sign phase
    ProofInPreSignPhase proof_in_pre_sign_phase_;
    ProofInSignPhase proof_in_sign_phase_;

    // culprit
    std::string identify_culprit_;
    int32_t identify_round_index_;
    bool identify_need_proof_in_pre_sign_phase_;
    bool identify_need_proof_in_sign_phase_;

};

}
}
}
}

#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_CONTEXT_H
