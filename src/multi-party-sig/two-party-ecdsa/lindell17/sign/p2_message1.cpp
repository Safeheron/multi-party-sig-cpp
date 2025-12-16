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
namespace sign {
bool P2Message1::ToProtoObject(safeheron::proto::two_party_ecdsa::lindell17::sign::P2Message1 &p2_msg1) const {
    bool ok = true;

    safeheron::proto::CurvePoint point_obj;
    ok = R2_.ToProtoObject(point_obj);
    if (!ok) return false;
    p2_msg1.mutable_r2()->CopyFrom(point_obj);

    safeheron::proto::DLogProof_V2 d_log_proof_obj;
    ok = d_log_proof_R2_.ToProtoObject(d_log_proof_obj);
    if (!ok) return false;
    p2_msg1.mutable_d_log_proof_r2()->CopyFrom(d_log_proof_obj);

    return true;
}

bool P2Message1::FromProtoObject(const safeheron::proto::two_party_ecdsa::lindell17::sign::P2Message1 &p2_msg1) {
    bool ok = R2_.FromProtoObject(p2_msg1.r2());
    if (!ok) return false;

    ok = d_log_proof_R2_.FromProtoObject(p2_msg1.d_log_proof_r2());
    if (!ok) return false;

    return true;
}

typedef P2Message1 TheClass;
typedef safeheron::proto::two_party_ecdsa::lindell17::sign::P2Message1 ProtoObject;

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

    return  true;
}

bool TheClass::FromJsonString(const std::string &json_str) {
    ProtoObject  proto_object;
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
