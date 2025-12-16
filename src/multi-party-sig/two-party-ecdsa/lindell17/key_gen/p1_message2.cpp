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

bool P1Message2::ToProtoObject(safeheron::proto::two_party_ecdsa::lindell17::key_gen::P1Message2 &p1_msg2) const {
    bool ok = true;

    safeheron::proto::CurvePoint point_obj;
    ok = Q1_.ToProtoObject(point_obj);
    if (!ok) return false;
    p1_msg2.mutable_q1()->CopyFrom(point_obj);

    safeheron::proto::DLogProof_V2 d_log_proof_obj;
    ok = d_log_proof_Q1_.ToProtoObject(d_log_proof_obj);
    if (!ok) return false;
    p1_msg2.mutable_d_log_proof_q1()->CopyFrom(d_log_proof_obj);

    p1_msg2.set_blind_factor(safeheron::encode::hex::EncodeToHex(blind_factor_));

    std::string str;
    c_.ToHexStr(str);
    p1_msg2.set_c(str);

    safeheron::proto::PailPub pail_pub_obj;
    ok = pail_pub_.ToProtoObject(pail_pub_obj);
    if (!ok) return false;
    p1_msg2.mutable_pail_pub()->CopyFrom(pail_pub_obj);

    safeheron::proto::PailNProof pail_n_proof_obj;
    ok = pail_n_proof_.ToProtoObject(pail_n_proof_obj);
    if (!ok) return false;
    p1_msg2.mutable_pail_n_proof()->CopyFrom(pail_n_proof_obj);

    return true;
}

bool P1Message2::FromProtoObject(const safeheron::proto::two_party_ecdsa::lindell17::key_gen::P1Message2 &p1_msg2) {
    bool ok = true;

    ok = Q1_.FromProtoObject(p1_msg2.q1());
    if (!ok) return false;

    ok = d_log_proof_Q1_.FromProtoObject(p1_msg2.d_log_proof_q1());
    if (!ok) return false;

    blind_factor_ = safeheron::encode::hex::DecodeFromHex(p1_msg2.blind_factor());

    c_ = safeheron::bignum::BN::FromHexStr(p1_msg2.c());

    ok = pail_pub_.FromProtoObject(p1_msg2.pail_pub());
    if (!ok) return false;

    ok = pail_n_proof_.FromProtoObject(p1_msg2.pail_n_proof());
    if (!ok) return false;

    return true;
}

typedef P1Message2 TheClass;
typedef safeheron::proto::two_party_ecdsa::lindell17::key_gen::P1Message2 ProtoObject;

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