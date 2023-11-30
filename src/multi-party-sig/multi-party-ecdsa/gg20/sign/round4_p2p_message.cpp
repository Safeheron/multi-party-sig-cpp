#include <google/protobuf/util/json_util.h>
#include "crypto-suites/crypto-encode/base64.h"
#include "multi-party-sig/multi-party-ecdsa/gg20/sign/message.h"

using std::string;
using safeheron::bignum::BN;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;


namespace safeheron {
namespace multi_party_ecdsa{
namespace gg20{
namespace sign{


bool Round4P2PMessage::ToProtoObject(safeheron::proto::multi_party_ecdsa::gg20::sign::Round4P2PMessage &message) const {
    bool ok = true;

    safeheron::proto::PailEncGroupEleRangeProof t_proof;
    ok = pail_enc_group_ele_range_proof_.ToProtoObject(t_proof);
    if (!ok) return false;
    message.mutable_pail_enc_group_ele_proof()->CopyFrom(t_proof);

    return true;
}

bool Round4P2PMessage::FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg20::sign::Round4P2PMessage &message) {
    bool ok = true;

    ok = pail_enc_group_ele_range_proof_.FromProtoObject(message.pail_enc_group_ele_proof());
    if (!ok) return false;

    return true;
}


typedef Round4P2PMessage TheClass;
typedef safeheron::proto::multi_party_ecdsa::gg20::sign::Round4P2PMessage ProtoObject;

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
