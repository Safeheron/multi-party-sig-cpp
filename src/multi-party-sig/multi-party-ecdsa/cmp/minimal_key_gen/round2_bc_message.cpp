#include <google/protobuf/util/json_util.h>
#include "crypto-suites/crypto-encode/base64.h"
#include "crypto-suites/crypto-encode/hex.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_key_gen/message.h"

using std::string;
using safeheron::bignum::BN;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;


namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace minimal_key_gen {


bool Round2BCMessage::ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::minimal_key_gen::Round2BCMessage &message) const {
    bool ok = true;

    string str;

    str = safeheron::encode::hex::EncodeToHex(sid_);
    message.set_sid(str);

    index_.ToHexStr(str);
    message.set_index(str);

    safeheron::proto::DLogProof_V2 dlog_proof_1;
    ok = psi_.ToProtoObject(dlog_proof_1);
    if (!ok) return false;
    message.mutable_psi()->CopyFrom(dlog_proof_1);

    safeheron::proto::DLogProof_V2 dlog_proof_2;
    ok = phi_.ToProtoObject(dlog_proof_2);
    if (!ok) return false;
    message.mutable_phi()->CopyFrom(dlog_proof_2);

    return true;
}

bool Round2BCMessage::FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::minimal_key_gen::Round2BCMessage &message) {
    bool ok = true;

    sid_ = safeheron::encode::hex::DecodeFromHex(message.sid());

    index_ = BN::FromHexStr(message.index());
    ok = (index_ != 0);
    if (!ok) return false;

    ok = psi_.FromProtoObject(message.psi());
    if (!ok) return false;

    ok = phi_.FromProtoObject(message.phi());
    if (!ok) return false;

    return true;
}

typedef Round2BCMessage TheClass;
typedef safeheron::proto::multi_party_ecdsa::cmp::minimal_key_gen::Round2BCMessage ProtoObject;

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
