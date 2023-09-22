import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:base32/base32.dart';
import 'package:bech32/bech32.dart';
import 'package:collection/collection.dart';
import 'package:crypto/crypto.dart';
import 'package:hex/hex.dart';
import 'package:pointycastle/export.dart';
import 'package:secp256k1/secp256k1.dart' as secp;
import 'package:tap_protocol/src/compat.dart';

final factoryRootKeys = [
  '03028a0e89e70d0ec0d932053a89ab1da7d9182bdc6d2f03e706ee99517d05d9e1',
  '027722ef208e681bac05f1b4b3cc478d6bf353ac9a09ff0c843430138f65c27bab',
];

Uint8List generateRandomBytes(int length) {
  final byteList = Uint8List(length);
  final random = Random.secure();

  for (var i = 0; i < length; i++) {
    byteList[i] = random.nextInt(256);
  }

  return byteList;
}

String cardPubKeyToIdent(Uint8List cardPubKey) {
  // convert pubkey into a hash formated for humans
  // - sha256(compressed-pubkey)
  // - skip first 8 bytes of that (because that's revealed in NFC URL)
  // - base32 and take first 20 chars in 4 groups of five
  // - insert dashes
  // - result is 23 chars long
  if (cardPubKey.length != 33) {
    throw Exception("expecting compressed pubkey");
  }

  final hashedPubKey = Uint8List.fromList(sha256.convert(cardPubKey).bytes);

  final md = base32.encode(hashedPubKey.sublist(8));

  var ident = '';
  for (int i = 0; i < 20; i += 5) {
    ident += "${md.substring(i, i + 5)}-";
  }
  return ident.substring(0, ident.length - 1);
}

const hardened = 0x80000000;

//  predicates for numeric paths. stop giggling
bool allHardened(List<int> path) {
  return path.every((element) => (element & hardened) != 0);
}

bool noneHardened(List<int> path) {
  return !path.any((element) => (element & hardened) != 0);
}

bool pathComponentInRange(int n) {
  // cannot be less than 0
  // cannot be more than (2 ** 31) - 1
  if (0 <= n && n < hardened) {
    return true;
  }
  return false;
}

String path2str(List<int> path) {
  var temp = [];
  for (var i = 0; i < path.length; i += 1) {
    var item = path[i];
    temp.add(
        (item & ~hardened).toString() + ((item & hardened != 0) ? 'h' : ''));
  }
  return ['m', ...temp].join('/');
}

List<int> str2path(String path) {
  // normalize notation and return numbers, no error checking
  List<int> rv = [];
  int here;

  final splitArr = path.split("/");

  for (int i = 0; i < splitArr.length; i++) {
    final item = splitArr[i];
    if (item == "m") {
      continue;
    }

    // if (!item) {
    //   // trailing or duplicated slashes
    //   continue;
    // }

    if ("'phHP".contains(item[item.length - 1])) {
      if (item.length < 2) {
        throw Exception("Malformed bip32 path component: $item");
      }
      final num = int.parse(item.substring(0, item.length - 1));

      if (!pathComponentInRange(num)) {
        throw Exception("Hardened path component out of range: $item");
      }
      here = (num | hardened) >>> 0;
    } else {
      here = int.parse(item);
      if (!pathComponentInRange(here)) {
        // cannot be less than 0
        // cannot be more than (2 ** 31) - 1
        throw Exception("Non-hardened path component out of range: $item");
      }
    }
    rv.add(here);
  }

  return (rv);
}

Uint8List pickNonce() {
  var noOfRetry = 3;

  for (var i = 0; i < noOfRetry; i++) {
    final nonce = generateRandomBytes(16);

    if (nonce.first != nonce.last || nonce.length >= 2) {
      return nonce;
    }
  }

  throw Exception('Cannot generate Nonce');
}

bool verifyCerts({
  required Map statusRes,
  required Map checkRes,
  required Map certsRes,
  required Uint8List nonce,
}) {
  final signatures = certsRes['cert_chain'] as List;
  if (signatures.length < 2) {
    throw Exception('Signatures too small');
  }

  final msg = [
    ...utf8.encode("OPENDIME"),
    ...statusRes["card_nonce"],
    ...nonce,
  ];

  if (msg.length != 8 + 16 + 16) {
    throw Exception('Invalid message length');
  }

  var pubKey = Uint8List.fromList(statusRes['pubkey']);

  final cardNonce = statusRes['card_nonce'];

  final msgDigest = Uint8List.fromList([
    ...Uint8List.fromList(utf8.encode("OPENDIME")),
    ...cardNonce,
    ...nonce,
  ]);

  final sig = Uint8List.fromList(checkRes['auth_sig']);

  final ok = ctSigVerify(
    sig: Uint8List.fromList(sig),
    msgDigest: msgDigest,
    pubKey: Uint8List.fromList(pubKey),
  );

  if (!ok) {
    throw Exception('bad sig in certificate verification');
  }

  for (var sig in signatures) {
    pubKey = ctSigToPubKey(
      Uint8List.fromList(sha256.convert(pubKey).bytes),
      Uint8List.fromList(List<int>.from(sig)),
    );
  }

  if (HEX.encode(pubKey) == factoryRootKeys.first) {
    return true;
  }

  return false;
}

Map<String, dynamic> calcXcvc(
  String cmd,
  Uint8List cardNonce,
  Uint8List cardPubKey,
  String cvc,
) {
  // Calcuate session key and xcvc value need for auth'ed commands
  // - also picks an arbitrary keypair for my side of the ECDH?
  // - requires pubkey from card and proposed CVC value
  if (cvc.length < 6 || cvc.length > 32) {
    throw Exception('Invalid cvc length');
  }
  final cvcBytes = Uint8List.fromList(cvc.codeUnits);

  // for (int i = 0; i < cvcBytes.length; i++) {
  //   cvcBytes[i] = int.parse(cvcBytes[i].toRadixString(16));
  // }

  // fresh new ephemeral key for our side of connection
  final keyPair = ctPickKeyPair();

  // standard ECDH
  // - result is sha256(compressed shared point (33 bytes))

  final hexPub = HEX.encode(cardPubKey);

  final sessionKey = Uint8List.fromList(ctEcdh(
    cardPubKey: secp.PublicKey.fromCompressedHex(hexPub),
    myPrivKey: keyPair.privKey,
  ));
  final message = [...cardNonce, ...utf8.encode(cmd)];

  final md = sha256.convert(message);
  final mask = xorBytes(sessionKey, Uint8List.fromList(md.bytes))
      .sublist(0, cvcBytes.length);
  final xcvc = xorBytes(cvcBytes, mask);

  print('session key is $sessionKey');
  return {
    "sk": sessionKey,
    "ag": {
      "epubkey": HEX.decode(keyPair.pubKey.toCompressedHex()),
      "xcvc": Uint8List.fromList(xcvc),
    },
  };
}

Uint8List xorBytes(Uint8List a, Uint8List b) {
  if (a.length != b.length) {
    print('a length is ${a.length} b is ${b.length}');
    print('a is $a b is $b');
    throw Exception('Length mismatch: Expected same lengths at xor_bytes');
  }
  final res = Uint8List(a.length);

  for (int i = 0; i < a.length; i++) {
    res[i] = a[i] ^ b[i];
  }

  return res;
}

Uint8List bigIntToUintList(BigInt bigInt) {
  final data = ByteData((bigInt.bitLength / 8).ceil());

  for (var i = 1; i <= data.lengthInBytes; i++) {
    data.setUint8(data.lengthInBytes - i, bigInt.toUnsigned(8).toInt());
    bigInt = bigInt >> 8;
  }

  return data.buffer.asUint8List(0);
}

bool compareList(Uint8List a, Uint8List b) {
  if (a.length != b.length) {
    return false;
  }

  return DeepCollectionEquality().equals(a, b);
}

String renderAddress({
  required Uint8List pubKey,
  bool isTestnet = false,
}) {
  // make the text string used as a payment address
  final hrp = isTestnet ? "tb" : "bc";

  final msgHash = hash160(pubKey);

  return segwit.encode(Segwit(hrp, 0, msgHash));
}

makeRecoverableSig({
  required Uint8List digest,
  required Uint8List sig,
  required Uint8List expectPubkey,
  bool isTestnet = false,
}) {
  // The card will only make non-recoverable signatures (64 bytes)
  // but we usually know the address which should be implied by
  // the signature's pubkey, so we can try all values and discover
  // the correct "recId"
  if (digest.length != 32) {
    throw Exception("Invalid digest length");
  }
  if (sig.length != 64) {
    throw Exception("Invalid sig length");
  }

  for (var recId = 0; recId < 4; recId++) {
    // see BIP-137 for magic value "39"... perhaps not well supported tho
    Uint8List? pubkey;
    Uint8List? recSig;
    try {
      recSig = Uint8List.fromList([39 + recId, ...sig]);

      pubkey = ctSigToPubKey(digest, recSig);
    } catch (e) {
      if (recId >= 2) {
        // because crypto I don't understand
        continue;
      }
    }
    //  Buffer.compare returns 0 if the buffers are equal
    if (pubkey != null && compareList(expectPubkey, pubkey)) {
      continue;
    }
    return recSig;
  }

  // failed to recover right pubkey value
  throw Exception("sig may not be created by that address/pubkey");
}

Uint8List hash160(Uint8List msg) {
  final shaRes = Uint8List.fromList(sha256.convert(msg).bytes);
  return RIPEMD160Digest().process(shaRes);
}
