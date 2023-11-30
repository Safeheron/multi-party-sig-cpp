#include <google/protobuf/util/json_util.h>
#include "crypto-suites/crypto-encode/base64.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign/message.h"

using std::string;
using safeheron::bignum::BN;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;


namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{
namespace sign{

bool Round5BCMessage::ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::sign::Round5BCMessage &message) const {
    bool ok = true;

    safeheron::proto::CurvePoint point;
    ok = V_.ToProtoObject(point);
    if (!ok) return false;
    message.mutable_v()->CopyFrom(point);

    ok = A_.ToProtoObject(point);
    if (!ok) return false;
    message.mutable_a()->CopyFrom(point);

    string str;
    blind_factor_.ToHexStr(str);
    message.set_blind_factor(str);

    safeheron::proto::LinearCombinationProof VRG_proof;
    ok = lc_proof_VRG_.ToProtoObject(VRG_proof);
    if (!ok) return false;
    message.mutable_lc_proof_vrg()->CopyFrom(VRG_proof);

    safeheron::proto::DLogProof_V2 dlog_proof;
    ok = dlog_proof_rho_.ToProtoObject(dlog_proof);
    if (!ok) return false;
    message.mutable_dlog_proof_rho()->CopyFrom(dlog_proof);

    return true;
}

bool Round5BCMessage::FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::sign::Round5BCMessage &message) {
    bool ok = true;

    ok = V_.FromProtoObject(message.v());
    if (!ok) return false;

    ok = A_.FromProtoObject(message.a());
    if (!ok) return false;

    blind_factor_ = BN::FromHexStr(message. blind_factor());

    ok = lc_proof_VRG_.FromProtoObject(message.lc_proof_vrg());
    if (!ok) return false;

    ok = dlog_proof_rho_.FromProtoObject(message.dlog_proof_rho());
    if (!ok) return false;

    return true;
}


typedef Round5BCMessage TheClass;
typedef safeheron::proto::multi_party_ecdsa::gg18::sign::Round5BCMessage ProtoObject;

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
