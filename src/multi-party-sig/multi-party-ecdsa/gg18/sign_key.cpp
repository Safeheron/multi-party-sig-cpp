#include <google/protobuf/util/json_util.h>
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-encode/base64.h"
#include "crypto-suites/crypto-sss/vsss.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign_key.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::sss::Polynomial;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::curve::CurveType;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;


namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{

int SignKey::get_remote_party_pos(const std::string &remote_party_id) const {
    int pos = -1;
    for (size_t i = 0; i < remote_parties_.size(); ++i) {
        if (remote_parties_[i].party_id_ == remote_party_id) {
            pos = i;
            break;
        }
    }
    return pos;
}

bool SignKey::ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::SignKey &sign_key) const {
    bool ok = true;
    string str;
    sign_key.set_workspace_id(workspace_id_);
    sign_key.set_threshold(threshold_);
    sign_key.set_n_parties(n_parties_);

    safeheron::proto::multi_party_ecdsa::gg18::Party local_party;
    ok = local_party_.ToProtoObject(local_party);
    if (!ok) return false;
    sign_key.mutable_local_party()->CopyFrom(local_party);

    for (size_t i = 0; i < remote_parties_.size(); i++) {
        safeheron::proto::multi_party_ecdsa::gg18::Party remote_party;
        ok = remote_parties_[i].ToProtoObject(remote_party);
        if (!ok) return false;
        safeheron::proto::multi_party_ecdsa::gg18::Party *new_party = sign_key.add_remote_parties();
        new_party->CopyFrom(remote_party);
    }

    safeheron::proto::CurvePoint point;
    ok = X_.ToProtoObject(point);
    if (!ok) return false;
    sign_key.mutable_g_x()->CopyFrom(point);

    return true;
}

bool SignKey::FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::SignKey &sign_key) {
    bool ok = true;

    workspace_id_ = sign_key.workspace_id();
    threshold_ = sign_key.threshold();
    n_parties_ = sign_key.n_parties();
    ok = (threshold_ > 0) && (threshold_ <= n_parties_);
    if (!ok) return false;

    ok = local_party_.FromProtoObject(sign_key.local_party());
    if (!ok) return false;

    RemoteParty party;
    for (int i = 0; i < sign_key.remote_parties_size(); i++) {
        ok = party.FromProtoObject(sign_key.remote_parties(i));
        if (!ok) return false;
        remote_parties_.push_back(party);
    }

    ok = X_.FromProtoObject(sign_key.g_x());
    ok = ok && !X_.IsInfinity();
    if (!ok) return false;

    return true;
}

bool SignKey::ValidityTest() const {
    bool ok = true;

    if(!X_.IsValid()) return false;

    const curve::Curve *curv = curve::GetCurveParam(X_.GetCurveType());

    // Step1: check g^u == y
    if (curv->g * local_party_.x_ != local_party_.g_x_) return false;

    // Step2: check pub == root_hd_key
    vector<BN> share_index_arr;
    for (size_t i = 0; i < remote_parties_.size(); ++i) {
        share_index_arr.push_back(remote_parties_[i].index_);
    }
    share_index_arr.push_back(local_party_.index_);

    vector<BN> l_arr;
    Polynomial::GetLArray(l_arr, BN::ZERO, share_index_arr, curv->n);

    CurvePoint pub = local_party_.g_x_ * l_arr[share_index_arr.size() - 1];
    for (size_t i = 0; i < remote_parties_.size(); ++i) {
        pub += remote_parties_[i].g_x_ * l_arr[i];
    }

    if (pub != X_) return false;

    return true;
}

typedef SignKey TheClass;
typedef safeheron::proto::multi_party_ecdsa::gg18::SignKey ProtoObject;

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
