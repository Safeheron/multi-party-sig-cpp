

#include <google/protobuf/util/json_util.h>
#include "crypto-suites/crypto-encode/base64.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/identification.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/message.h"

using std::string;
using safeheron::bignum::BN;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;


namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace sign {


bool ProofInPreSignPhase::ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::sign::ProofInPreSignPhase &message) const {
    bool ok = true;

    std::string str;

    c_k_gamma_.ToHexStr(str);
    message.set_c_k_gamma(str);

    for (auto & pair : id_map_map_) {
        for (auto & id_map_pair : pair.second) {
            safeheron::proto::PailAffGroupEleRangeProof_V2 t_aff_g_proof;
            ok = id_map_pair.second.ToProtoObject(t_aff_g_proof);
            if (!ok) return false;
            if(!message.mutable_id_map_map()->contains(pair.first)){
                (*message.mutable_id_map_map())[pair.first] = safeheron::proto::multi_party_ecdsa::cmp::sign::ProofInPreSignPhase_IDAffGProofMap();
            }
            auto & t_map = (*message.mutable_id_map_map())[pair.first];
            (*t_map.mutable_id_aff_g_proof_map())[id_map_pair.first] = t_aff_g_proof;
        }
    }

    safeheron::proto::PailEncMulProof t_pail_enc_mul_proof;
    ok = pail_enc_mul_proof_.ToProtoObject(t_pail_enc_mul_proof);
    if (!ok) return false;
    message.mutable_pail_enc_mul_proof()->CopyFrom(t_pail_enc_mul_proof);

    for (auto & pair : id_dec_proof_map_) {
        safeheron::proto::PailDecModuloProof t_pail_dec_proof;
        ok = pair.second.ToProtoObject(t_pail_dec_proof);
        if (!ok) return false;
        (*message.mutable_id_dec_proof_map())[pair.first] = t_pail_dec_proof;
    }

    return true;
}

bool ProofInPreSignPhase::FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::sign::ProofInPreSignPhase &message) {
    bool ok = true;

    c_k_gamma_ = BN::FromHexStr(message.c_k_gamma());

    if(message.id_map_map_size() <= 0 ) return false;

    if(!message.has_pail_enc_mul_proof()) return false;

    if(message.id_dec_proof_map_size() <= 0) return false;

    for (auto & pair : message.id_map_map()){
        if(pair.second.id_aff_g_proof_map_size() <= 0 ) return false;
        for (auto & id_proof_pair : pair.second.id_aff_g_proof_map()){
            safeheron::zkp::pail::PailAffGroupEleRangeProof_V2 t_aff_g_proof;
            ok = t_aff_g_proof.FromProtoObject(id_proof_pair.second);
            if (!ok) return false;
            id_map_map_[pair.first][id_proof_pair.first] = t_aff_g_proof;
        }
    }

    ok = pail_enc_mul_proof_.FromProtoObject(message.pail_enc_mul_proof());
    if (!ok) return false;

    for (auto & pair : message.id_dec_proof_map()){
        safeheron::zkp::pail::PailDecModuloProof t_pail_dec_proof;
        ok = t_pail_dec_proof.FromProtoObject(pair.second);
        if (!ok) return false;
        id_dec_proof_map_[pair.first] = t_pail_dec_proof;
    }

    return true;
}


typedef ProofInPreSignPhase TheClass;
typedef safeheron::proto::multi_party_ecdsa::cmp::sign::ProofInPreSignPhase ProtoObject;

bool TheClass::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    ProtoObject proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = safeheron::encode::base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool TheClass::FromBase64(const string &b64) {
    bool ok = true;

    string data = safeheron::encode::base64::DecodeFromBase64(b64);

    ProtoObject proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool TheClass::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    ProtoObject proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}


bool TheClass::FromJsonString(const string &json_str) {
    ProtoObject proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
}
