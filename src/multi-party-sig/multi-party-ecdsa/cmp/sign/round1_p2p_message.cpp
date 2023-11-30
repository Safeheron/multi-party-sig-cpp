#include <google/protobuf/util/json_util.h>
#include "crypto-suites/crypto-encode/base64.h"
#include "crypto-suites/crypto-encode/hex.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/message.h"


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
namespace sign {


bool Round1P2PMessage::ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::sign::Round1P2PMessage &message) const {
    bool ok = true;

    string str;

    str = safeheron::encode::hex::EncodeToHex(ssid_);
    message.set_ssid(str);

    index_.ToHexStr(str);
    message.set_index(str);

    safeheron::proto::CurvePoint point;
    ok = Gamma_.ToProtoObject(point);
    if (!ok) return false;
    message.mutable_g_gamma()->CopyFrom(point);

    D_ij_.ToHexStr(str);
    message.set_d_ij(str);

    F_ij_.ToHexStr(str);
    message.set_f_ij(str);

    D_hat_ij_.ToHexStr(str);
    message.set_d_hat_ij(str);

    F_hat_ij_.ToHexStr(str);
    message.set_f_hat_ij(str);

    safeheron::proto::PailAffGroupEleRangeProof_V2 t_proof_1;
    ok = psi_ij_.ToProtoObject(t_proof_1);
    if (!ok) return false;
    message.mutable_psi_ij()->CopyFrom(t_proof_1);

    safeheron::proto::PailAffGroupEleRangeProof_V2 t_proof_2;
    ok = psi_hat_ij_.ToProtoObject(t_proof_2);
    if (!ok) return false;
    message.mutable_psi_hat_ij()->CopyFrom(t_proof_2);

    safeheron::proto::PailEncGroupEleRangeProof t_proof_3;
    ok = psi_prime_ij_.ToProtoObject(t_proof_3);
    if (!ok) return false;
    message.mutable_psi_prime_ij()->CopyFrom(t_proof_3);

    return true;
}

bool Round1P2PMessage::FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::sign::Round1P2PMessage &message) {
    bool ok = true;

    ssid_ = safeheron::encode::hex::DecodeFromHex(message.ssid());

    index_ = BN::FromHexStr(message.index());
    ok = (index_ != 0);
    if (!ok) return false;

    ok = Gamma_.FromProtoObject(message.g_gamma());
    if (!ok) return false;

    D_ij_ = BN::FromHexStr(message.d_ij());

    F_ij_ = BN::FromHexStr(message.f_ij());

    D_hat_ij_ = BN::FromHexStr(message.d_hat_ij());

    F_hat_ij_ = BN::FromHexStr(message.f_hat_ij());

    ok = psi_ij_.FromProtoObject(message.psi_ij());
    if (!ok) return false;

    ok = psi_hat_ij_.FromProtoObject(message.psi_hat_ij());
    if (!ok) return false;

    ok = psi_prime_ij_.FromProtoObject(message.psi_prime_ij());
    if (!ok) return false;

    return true;
}


typedef Round1P2PMessage TheClass;
typedef safeheron::proto::multi_party_ecdsa::cmp::sign::Round1P2PMessage ProtoObject;


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
