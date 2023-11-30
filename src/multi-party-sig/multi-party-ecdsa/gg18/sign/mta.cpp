#include <google/protobuf/util/json_util.h>
#include "crypto-suites/crypto-hash/sha256.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-encode/base64.h"
#include "crypto-suites/exception/located_exception.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign/mta.h"

using std::string;
using std::vector;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
using namespace safeheron::rand;
using namespace safeheron::encode;

namespace safeheron {
namespace multi_party_ecdsa {
namespace gg18 {
namespace sign {

void
MtA_Step1(BN &message_a, const pail::PailPubKey &pail_pub, const BN &input_a, const BN &r_lt_pailN) {
    message_a = pail_pub.EncryptWithR(input_a, r_lt_pailN);
}

void
MtA_Step2(safeheron::bignum::BN &message_b, safeheron::bignum::BN &beta, const pail::PailPubKey &pub,
          const safeheron::bignum::BN &input_b,
          const safeheron::bignum::BN &message_a, const safeheron::bignum::BN &beta_tag,
          const safeheron::bignum::BN &r_for_pail, const safeheron::bignum::BN &order) {
    const BN &c_a = message_a;

    BN bma = pub.HomomorphicMulPlain(c_a, input_b);
    BN c_b = pub.HomomorphicAddPlainWithR(bma, beta_tag, r_for_pail);

    beta = beta_tag.Neg() % order;
    message_b = c_b;
}

void MtA_Step3(BN &alpha, const safeheron::bignum::BN &message_b, const pail::PailPrivKey &pail_priv,
               const safeheron::bignum::BN &order) {
    alpha = pail_priv.Decrypt(message_b);
    alpha = alpha % order;
}

}
}
}
}
