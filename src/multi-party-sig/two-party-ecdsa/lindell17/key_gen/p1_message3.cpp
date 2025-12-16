#include "message.h"
#include <google/protobuf/util/json_util.h>
#include "crypto-suites/crypto-encode/hex.h"
#include "crypto-suites/crypto-encode/base64.h"
#include <google/protobuf/port_def.inc>
#include <google/protobuf/port_undef.inc>
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;

namespace safeheron {
namespace two_party_ecdsa {
namespace lindell17 {
namespace key_gen {
bool P1Message3::ToProtoObject(safeheron::proto::two_party_ecdsa::lindell17::key_gen::P1Message3 &p1_msg3) const {
    safeheron::proto::PDLPMessage1 pdl_p_msg1_obj;
    if (!pdl_p_message1_.ToProtoObject(pdl_p_msg1_obj)) return false;
    p1_msg3.mutable_pdl_p_message1()->CopyFrom(pdl_p_msg1_obj);

    return true;
}

bool P1Message3::FromProtoObject(const safeheron::proto::two_party_ecdsa::lindell17::key_gen::P1Message3 &p1_msg3) {
    pdl_p_message1_.FromProtoObject(p1_msg3.pdl_p_message1());
    return true;
}

typedef P1Message3 TheClass;
typedef safeheron::proto::two_party_ecdsa::lindell17::key_gen::P1Message3 ProtoObject;

bool TheClass::ToBase64(std::string &b64) const {
    bool ok = true;
    b64.clear();
    ProtoObject proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    std::string proto_bin = proto_object.SerializeAsString();
    b64 = safeheron::encode::base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool TheClass::FromBase64(const std::string &b64) {
    bool ok = true;

    std::string data = safeheron::encode::base64::DecodeFromBase64(b64);

    ProtoObject proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool TheClass::ToJsonString(std::string &json_str) const {
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

bool TheClass::FromJsonString(const std::string &json_str) {
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
