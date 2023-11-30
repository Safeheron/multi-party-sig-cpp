#include <google/protobuf/util/json_util.h>
#include "crypto-suites/crypto-encode/base64.h"
#include "crypto-suites/crypto-encode/hex.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_refresh/message.h"

using std::string;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;


namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{
namespace key_refresh {

bool Round1BCMessage::ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::key_refresh::Round1BCMessage &message) const {
    bool ok = true;

    for(size_t i = 0; i < vs_.size(); ++i){
        safeheron::proto::CurvePoint * point_ptr = message.mutable_vs()->Add();
        ok = vs_[i].ToProtoObject(*point_ptr);
        if (!ok) return false;
    }

    string str;
    N_tilde_.ToHexStr(str);
    message.set_n_tilde(str);

    h1_.ToHexStr(str);
    message.set_h1(str);

    h2_.ToHexStr(str);
    message.set_h2(str);

    safeheron::proto::DLNProof t_dln_proof1;
    ok = dln_proof_1_.ToProtoObject(t_dln_proof1);
    if (!ok) return false;
    message.mutable_dln_proof_1()->CopyFrom(t_dln_proof1);

    safeheron::proto::DLNProof t_dln_proof2;
    ok = dln_proof_2_.ToProtoObject(t_dln_proof2);
    if (!ok) return false;
    message.mutable_dln_proof_2()->CopyFrom(t_dln_proof2);

    safeheron::proto::PailPub t_pail_pub;
    ok = pail_pub_.ToProtoObject(t_pail_pub);
    if (!ok) return false;
    message.mutable_pail_pub()->CopyFrom(t_pail_pub);

    str = safeheron::encode::hex::EncodeToHex(blind_factor_);
    message.set_blind_factor(str);

    return true;
}

bool Round1BCMessage::FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::key_refresh::Round1BCMessage &message) {
    bool ok = true;

    for(int i = 0; i < message.vs_size(); ++i){
        CurvePoint point;
        ok = point.FromProtoObject(message.vs(i));
        if (!ok) return false;
        vs_.push_back(point);
    }

    N_tilde_ = BN::FromHexStr(message.n_tilde());
    ok = (N_tilde_ != 0);
    if (!ok) return false;

    h1_ = BN::FromHexStr(message.h1());
    ok = (h1_ != 0);
    if (!ok) return false;

    h2_ = BN::FromHexStr(message.h2());
    ok = (h2_ != 0);
    if (!ok) return false;

    ok = dln_proof_1_.FromProtoObject(message.dln_proof_1());
    if (!ok) return false;

    ok = dln_proof_2_.FromProtoObject(message.dln_proof_2());
    if (!ok) return false;

    ok = pail_pub_.FromProtoObject(message.pail_pub());
    if (!ok) return false;

    blind_factor_ = safeheron::encode::hex::DecodeFromHex(message.blind_factor());

    return true;
}


typedef Round1BCMessage TheClass;
typedef safeheron::proto::multi_party_ecdsa::gg18::key_refresh::Round1BCMessage ProtoObject;

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
