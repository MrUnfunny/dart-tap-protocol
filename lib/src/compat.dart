import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:dart_secp256k1/dart_secp256k1.dart';
import 'package:hex/hex.dart';
import 'package:secp256k1/secp256k1.dart' as secp;
import 'package:tap_protocol/src/utils.dart';

class CTKeyPair {
  final secp.PrivateKey privKey;
  final secp.PublicKey pubKey;

  CTKeyPair({
    required this.privKey,
    required this.pubKey,
  });
}

CTKeyPair ctPickKeyPair() {
  //TODO: try to generate with a random seed and verify private key
  // final priv = secp.PrivateKey.generate();

  final priv = secp.PrivateKey.fromHex(
    "ffba10fb254db004c760fe24402012c6aec3ed2e7efb7d779a533a4492dae18b",
  );

  final pub = priv.publicKey;

  print("pub key is ${pub.toCompressedHex()}");

  return CTKeyPair(privKey: priv, pubKey: pub);
}

int recIdFromHeader(header) {
  var headerNum = header & 0xff;
  if (headerNum >= 39) {
    headerNum -= 12;
  } else if (headerNum >= 35) {
    headerNum -= 8;
  } else if (headerNum >= 31) {
    headerNum -= 4;
  }
  final recId = headerNum - 27;
  return recId;
}

Uint8List ctSigToPubKey(Uint8List msgDigest, Uint8List sig) {
  // returns a pubkey (33 bytes)
  final secp = Secp256k1(
    DynamicLibrary.open(
        "../rnd/dart-secp256k1/native/build/libsecp256k1.dylib"),
  );

  final header = sig[0];
  final recId = recIdFromHeader(header);

  final compactSignature = sig.sublist(1);

  final resPubKey = secp.ecdsaRecover(compactSignature, msgDigest, recId);
  return Uint8List.fromList(resPubKey);
}

bool ctSigVerify({
  required Uint8List sig,
  required Uint8List msgDigest,
  required Uint8List pubKey,
}) {
  final rHex = HEX.encode(sig.sublist(0, 32));
  final sHex = HEX.encode(sig.sublist(32));

  final pubHex = HEX.encode(pubKey);
  final signature = secp.Signature.fromHexes(rHex, sHex);

  final publicKey = secp.PublicKey.fromCompressedHex(pubHex);

  final digest = sha256.convert(msgDigest);

  final verified = signature.verify(publicKey, HEX.encode(digest.bytes));

  return verified;
}

List<int> ctEcdh({
  required secp.PublicKey cardPubKey,
  required secp.PrivateKey myPrivKey,
}) {
  //TODO: find better way to load dylib
  final secp = Secp256k1(
    DynamicLibrary.open(
        "../rnd/dart-secp256k1/native/build/libsecp256k1.dylib"),
  );

  final secret = secp.ecdh(
    bigIntToUintList(myPrivKey.D),
    Secp256k1PublicKey.fromHex(cardPubKey.toHex()),
  );

  return secret;
}
