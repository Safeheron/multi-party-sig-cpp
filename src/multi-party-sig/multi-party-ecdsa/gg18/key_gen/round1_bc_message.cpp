#include <google/protobuf/util/json_util.h>
#include "crypto-suites/crypto-encode/base64.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_gen/message.h"

using std::string;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;


namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{
namespace key_gen {



bool Round1BCMessage::ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::key_gen::Round1BCMessage &message) const {
    bool ok = true;

    safeheron::proto::KGD kgdPoint;
    ok = kgd_y_.ToProtoObject(kgdPoint);
    if (!ok) return false;
    message.mutable_kgd_y()->CopyFrom(kgdPoint);

    for(size_t i = 0; i < vs_.size(); ++i){
        safeheron::proto::CurvePoint * point_ptr = message.mutable_vs()->Add();
        ok = vs_[i].ToProtoObject(*point_ptr);
        if (!ok) return false;
    }
    return true;
}

bool Round1BCMessage::FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::key_gen::Round1BCMessage &message) {
    bool ret = true;

    ret = kgd_y_.FromProtoObject(message.kgd_y());
    if (!ret) return false;

    for(int i = 0; i < message.vs_size(); ++i){
        CurvePoint point;
        bool ok = point.FromProtoObject(message.vs(i));
        if (!ok) return false;
        vs_.push_back(point);
    }
    return true;
}


typedef Round1BCMessage TheClass;
typedef safeheron::proto::multi_party_ecdsa::gg18::key_gen::Round1BCMessage ProtoObject;

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
