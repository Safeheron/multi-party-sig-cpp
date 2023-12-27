#include <google/protobuf/util/json_util.h>
#include "crypto-suites/crypto-encode/base64.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/key_recovery/message.h"

using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;

namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {
namespace key_recovery {
bool Round1P2PMessage::ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::key_recovery::Round1P2PMessage &message) const {
    bool ok = true;

    std::string str;
    safeheron::proto::CurvePoint point;
    safeheron::proto::DLogProof_V2 dlog_proof;

    ok = X_.ToProtoObject(point);
    if (!ok) return false;
    message.mutable_x()->CopyFrom(point);

    i_.ToHexStr(str);
    message.set_i(str);

    j_.ToHexStr(str);
    message.set_j(str);

    k_.ToHexStr(str);
    message.set_k(str);

    ok = A_.ToProtoObject(point);
    if (!ok) return false;
    message.mutable_a()->CopyFrom(point);

    ok = R_.ToProtoObject(point);
    if (!ok) return false;
    message.mutable_r()->CopyFrom(point);

    ok = T_.ToProtoObject(point);
    if (!ok) return false;
    message.mutable_t()->CopyFrom(point);

    ok = phi_.ToProtoObject(dlog_proof);
    if (!ok) return false;
    message.mutable_phi()->CopyFrom(dlog_proof);

    return true;
}

bool Round1P2PMessage::FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::key_recovery::Round1P2PMessage &message) {

    bool ok = X_.FromProtoObject(message.x());
    if (!ok) return false;
    //lack of try catch
    i_ = safeheron::bignum::BN::FromHexStr(message.i());
    ok = (i_ != 0);
    if (!ok) return false;

    j_ = safeheron::bignum::BN::FromHexStr(message.j());
    ok = (j_ != 0);
    if (!ok) return false;

    k_ = safeheron::bignum::BN::FromHexStr(message.k());
    ok = (k_ != 0);
    if (!ok) return false;

    ok = A_.FromProtoObject(message.a());
    if (!ok) return false;

    ok = R_.FromProtoObject(message.r());
    if (!ok) return false;

    ok = T_.FromProtoObject(message.t());
    if (!ok) return false;

    ok = phi_.FromProtoObject(message.phi());
    if (!ok) return false;

    return true;
}

typedef Round1P2PMessage TheClass;
typedef safeheron::proto::multi_party_ecdsa::cmp::key_recovery::Round1P2PMessage ProtoObject;

bool Round1P2PMessage::ToBase64(std::string &b64) const {
    bool ok = true;
    b64.clear();
    ProtoObject proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    std::string proto_bin = proto_object.SerializeAsString();
    b64 = safeheron::encode::base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool Round1P2PMessage::FromBase64(const std::string &b64) {
    bool ok = true;

    std::string data = safeheron::encode::base64::DecodeFromBase64(b64);

    ProtoObject proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool Round1P2PMessage::ToJsonString(std::string &json_str) const {
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

bool Round1P2PMessage::FromJsonString(const std::string &json_str) {
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
