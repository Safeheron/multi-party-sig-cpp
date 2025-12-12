#include "P2KeyShare.h"
#include <google/protobuf/util/json_util.h>
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
bool P2KeyShare::ToProtoObject(safeheron::proto::two_party_ecdsa::lindell17::P2KeyShare &p2_key_share) const {
    bool ok = true;

    std::string str;
    x2_.ToHexStr(str);
    p2_key_share.set_x2(str);

    safeheron::proto::CurvePoint Q;
    ok = Q_.ToProtoObject(Q);
    if (!ok) return false;
    p2_key_share.mutable_q()->CopyFrom(Q);

    safeheron::proto::PailPub pail_pub;
    ok = pail_pub_.ToProtoObject(pail_pub);
    if (!ok) return false;
    p2_key_share.mutable_pail_pub()->CopyFrom(pail_pub);

    c_.ToHexStr(str);
    p2_key_share.set_c(str);

    return true;
}

bool P2KeyShare::FromProtoObject(const safeheron::proto::two_party_ecdsa::lindell17::P2KeyShare &p2_key_share) {
    bool ok = true;

    x2_ = safeheron::bignum::BN::FromHexStr(p2_key_share.x2());

    ok = Q_.FromProtoObject(p2_key_share.q());
    if (!ok) return false;

    ok = pail_pub_.FromProtoObject(p2_key_share.pail_pub());
    if (!ok) return false;

    c_ = safeheron::bignum::BN::FromHexStr(p2_key_share.c());

    return true;
}

typedef P2KeyShare TheClass;
typedef safeheron::proto::two_party_ecdsa::lindell17::P2KeyShare ProtoObject;

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
