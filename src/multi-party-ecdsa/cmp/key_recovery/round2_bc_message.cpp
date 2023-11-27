#include "message.h"
#include <google/protobuf/util/json_util.h>
#include "crypto-encode/base64.h"

using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;

namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {
namespace key_recovery {
bool Round2BCMessage::ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::key_recovery::Round2BCMessage &message) const {
    bool ok = true;

    safeheron::proto::CurvePoint point ;
    safeheron::proto::DLogProof_V2 dlog_proof;

    ok = S_.ToProtoObject(point);
    if (!ok) return false;
    message.mutable_s()->CopyFrom(point);

    ok = psi_.ToProtoObject(dlog_proof);
    if (!ok) return false;
    message.mutable_psi()->CopyFrom(dlog_proof);

    return true;
}

bool Round2BCMessage::FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::key_recovery::Round2BCMessage &message) {
    bool ok = S_.FromProtoObject(message.s());
    if (!ok) return false;

    ok = psi_.FromProtoObject(message.psi());
    if (!ok) return false;

    return true;
}

typedef Round1BCMessage TheClass;
typedef safeheron::proto::multi_party_ecdsa::cmp::key_recovery::Round2BCMessage ProtoObject;

bool Round2BCMessage::ToBase64(std::string &b64) const {
    bool ok = true;
    b64.clear();
    ProtoObject proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    std::string proto_bin = proto_object.SerializeAsString();
    b64 = safeheron::encode::base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool Round2BCMessage::FromBase64(const std::string &b64) {
    bool ok = true;

    std::string data = safeheron::encode::base64::DecodeFromBase64(b64);

    ProtoObject proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool Round2BCMessage::ToJsonString(std::string &json_str) const {
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

bool Round2BCMessage::FromJsonString(const std::string &json_str) {
    ProtoObject proto_object;
    JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}
}
}
}
}
