#include <google/protobuf/util/json_util.h>
#include "crypto-suites/crypto-encode/base64.h"
#include "crypto-suites/crypto-encode/hex.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_key_gen/message.h"

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
namespace cmp{
namespace minimal_key_gen {

bool Round1BCMessage::ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::minimal_key_gen::Round1BCMessage &message) const {
    bool ok = true;

    string str;

    str = safeheron::encode::hex::EncodeToHex(sid_);
    message.set_sid(str);

    index_.ToHexStr(str);
    message.set_index(str);

    str = safeheron::encode::hex::EncodeToHex(rid_);
    message.set_rid(str);

    safeheron::proto::CurvePoint point;
    ok = X_.ToProtoObject(point);
    if (!ok) return false;
    message.mutable_g_x()->CopyFrom(point);

    ok = A_.ToProtoObject(point);
    if (!ok) return false;
    message.mutable_a()->CopyFrom(point);

    ok = B_.ToProtoObject(point);
    if (!ok) return false;
    message.mutable_b()->CopyFrom(point);

    for(const auto &item :map_party_id_X_){
        message.add_party_id_arr_1(item.first);

        safeheron::proto::CurvePoint * point_ptr = message.mutable_g_x_arr()->Add();
        ok = item.second.ToProtoObject(*point_ptr);
        if (!ok) return false;
    }

    for(size_t i = 0; i < c_.size(); ++i){
        safeheron::proto::CurvePoint * point_ptr = message.mutable_c()->Add();
        ok = c_[i].ToProtoObject(*point_ptr);
        if (!ok) return false;
    }

    str = safeheron::encode::hex::EncodeToHex(u_);
    message.set_u(str);

    return true;
}

bool Round1BCMessage::FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::minimal_key_gen::Round1BCMessage &message) {
    bool ok = true;

    sid_ = safeheron::encode::hex::DecodeFromHex(message.sid());

    index_ = BN::FromHexStr(message.index());
    ok = (index_ != 0);
    if (!ok) return false;

    rid_ = safeheron::encode::hex::DecodeFromHex(message.rid());

    ok = X_.FromProtoObject(message.g_x());
    ok = ok && !X_.IsInfinity();
    if (!ok) return false;

    ok = A_.FromProtoObject(message.a());
    if (!ok) return false;

    ok = B_.FromProtoObject(message.b());
    if (!ok) return false;

    std::vector<std::string> party_id_arr_1;
    std::vector<safeheron::curve::CurvePoint> X_arr;
    size_t party_count = message.party_id_arr_1_size();
    ok = ( party_count == (size_t)message.g_x_arr_size() );
    if (!ok) return false;
    for(int i = 0; i < message.party_id_arr_1_size(); ++i){
        string party_id;
        CurvePoint X;
        party_id = message.party_id_arr_1(i);
        ok = X.FromProtoObject(message.g_x_arr(i));
        if (!ok) return false;
        map_party_id_X_[party_id] = X;
    }
    ok = party_count == map_party_id_X_.size();
    if (!ok) return false;

    for(int i = 0; i < message.c_size(); ++i){
        CurvePoint point;
        bool ok = point.FromProtoObject(message.c(i));
        if (!ok) return false;
        c_.push_back(point);
    }

    u_ = safeheron::encode::hex::DecodeFromHex(message.u());

    return true;
}


typedef Round1BCMessage TheClass;
typedef safeheron::proto::multi_party_ecdsa::cmp::minimal_key_gen::Round1BCMessage ProtoObject;

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
