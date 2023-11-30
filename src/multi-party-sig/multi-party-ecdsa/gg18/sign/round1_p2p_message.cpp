#include <google/protobuf/util/json_util.h>
#include "crypto-suites/crypto-encode/base64.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign/message.h"

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
namespace sign{

bool Round1P2PMessage::ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::sign::Round1P2PMessage &message) const {
    bool ok = true;

    string str;
    message_b_for_k_gamma_.ToHexStr(str);
    message.set_message_b_for_k_gamma(str);

    message_b_for_k_w_.ToHexStr(str);
    message.set_message_b_for_k_w(str);

    safeheron::proto::PailAffRangeProof t_bob_proof_1;
    ok = bob_proof_1_.ToProtoObject(t_bob_proof_1);
    if (!ok) return false;
    message.mutable_bob_proof_1()->CopyFrom(t_bob_proof_1);

    safeheron::proto::PailAffGroupEleRangeProof_V1 t_bob_proof_2;
    ok = bob_proof_2_.ToProtoObject(t_bob_proof_2);
    if (!ok) return false;
    message.mutable_bob_proof_2()->CopyFrom(t_bob_proof_2);

    return true;
}

bool Round1P2PMessage::FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::sign::Round1P2PMessage &message) {
    bool ok = true;

    message_b_for_k_gamma_ = BN::FromHexStr(message.message_b_for_k_gamma());
    message_b_for_k_w_ = BN::FromHexStr(message.message_b_for_k_w());

    ok = bob_proof_1_.FromProtoObject(message.bob_proof_1());
    if (!ok) return false;

    ok = bob_proof_2_.FromProtoObject(message.bob_proof_2());
    if (!ok) return false;

    return true;
}


typedef Round1P2PMessage TheClass;
typedef safeheron::proto::multi_party_ecdsa::gg18::sign::Round1P2PMessage ProtoObject;

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
