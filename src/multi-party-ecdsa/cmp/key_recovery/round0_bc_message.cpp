#include "message.h"
#include <google/protobuf/util/json_util.h>
#include "crypto-encode/base64.h"
#include "crypto-encode/hex.h"

using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;

namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {
namespace key_recovery {

bool Round0BCMessage::ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::key_recovery::Round0BCMessage &message) const {
    std::string str = safeheron::encode::hex::EncodeToHex(V_);
    message.set_v(str);
    return true;
}

bool Round0BCMessage::FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::key_recovery::Round0BCMessage &message) {
    V_ = safeheron::encode::hex::DecodeFromHex(message.v());
    return true;
}

typedef Round0BCMessage TheClass;
typedef safeheron::proto::multi_party_ecdsa::cmp::key_recovery::Round0BCMessage ProtoObject;

bool Round0BCMessage::ToBase64(std::string &b64) const {
    bool ok = true;
    b64.clear();
    ProtoObject proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    std::string proto_bin = proto_object.SerializeAsString();
    b64 = safeheron::encode::base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool Round0BCMessage::FromBase64(const std::string &b64) {
    bool ok = true;

    std::string data = safeheron::encode::base64::DecodeFromBase64(b64);

    ProtoObject proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool Round0BCMessage::ToJsonString(std::string &json_str) const {
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

bool Round0BCMessage::FromJsonString(const std::string &json_str) {
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