
#include "message.h"

#include <google/protobuf/util/json_util.h>
#include "crypto-encode/base64.h"

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
namespace key_gen {


bool Round2BCMessage::ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::key_gen::Round2BCMessage &message) const {
    bool ok = true;

    safeheron::proto::DLogProof dlog_proof;
    ok = dlog_proof_x_.ToProtoObject(dlog_proof);
    if (!ok) return false;
    message.mutable_dlog_proof_x()->CopyFrom(dlog_proof);

    safeheron::proto::CurvePoint point;
    ok = pub_.ToProtoObject(point);
    if (!ok) return false;
    message.mutable_pub()->CopyFrom(point);

    safeheron::proto::PailBlumModulusProof pail_proof;
    ok = pail_proof_.ToProtoObject(pail_proof);
    if (!ok) return false;
    message.mutable_pail_proof()->CopyFrom(pail_proof);

    return true;
}

bool Round2BCMessage::FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::key_gen::Round2BCMessage &message) {
    bool ok = dlog_proof_x_.FromProtoObject(message.dlog_proof_x());
    if (!ok) return false;

    ok = pub_.FromProtoObject(message.pub());
    ok = ok && !pub_.IsInfinity();
    if (!ok) return false;

    ok = pail_proof_.FromProtoObject(message.pail_proof());
    if (!ok) return false;

    return true;
}

typedef Round2BCMessage TheClass;
typedef safeheron::proto::multi_party_ecdsa::gg18::key_gen::Round2BCMessage ProtoObject;

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
