import 'dart:convert';
import 'dart:typed_data';
import 'package:hex/hex.dart';
import 'package:secp256k1/secp256k1.dart';
import 'package:tap_protocol/src/compat.dart';
import 'package:tap_protocol/src/protocol.dart';
import 'package:tap_protocol/src/utils.dart';

void main(List<String> arguments) async {
  trdy();
  return;
  final card = CkTapCard();

  card.certificateCheck();

  // await card.firstLook();
  // final res = await card.read("123456");
  // final digest = generateRandomBytes(32);
  // final res = await card.sendAuth(
  //   cmd: "sign",
  //   cvc: "123456",
  //   args: {
  //     "subpath": [0, 0],
  //     "digest": digest,
  //   },
  // );

  // await card.setup(
  //   cvc: "123456",
  //   newChainCode: false,
  // );

  // print("res is");
  // print(res);
}

testFunc() {
  var verPrv = PrivateKey.fromHex(
    "ffba10fb254db004c760fe24402012c6aec3ed2e7efb7d779a533a4492dae18b",
  );

  var pubKey = PublicKey.fromCompressedHex(
    '023b5ac2b005c78297272c0f5dbeefd88cec42db09392ac7cb1e2c64689ca1fe63',
  );

  var privKey = PrivateKey.fromHex(
    'd7fe9b49d0631e36828cbcc7f4af8b293e443ca840dfb89aef4f4ab05e1fb307',
  );

  print('pubs  prv key is \n${verPrv.toHex()}');
  print('pubs  pub key is \n${verPrv.publicKey.toCompressedHex()}\n\n');

  print('prvs priv key is ${privKey.toHex()}');
  print('prvs pub key is ${privKey.publicKey.toCompressedHex()}\n\n');

  final res = ctEcdh(cardPubKey: pubKey, myPrivKey: privKey);

  print(res);
}

void trdy() {
  var cardPubKey = [
    3,
    50,
    131,
    14,
    50,
    9,
    233,
    80,
    149,
    122,
    211,
    150,
    76,
    34,
    63,
    136,
    248,
    223,
    97,
    218,
    210,
    247,
    22,
    8,
    127,
    92,
    51,
    109,
    166,
    51,
    114,
    165,
    110,
  ];

  final pubhex = HEX.encode(cardPubKey);
  print(pubhex);

  return;

  var ident = cardPubKeyToIdent(Uint8List.fromList(cardPubKey));
  print(ident);
  return;
  var a1 = "023b5ac2b005c78297272c0f5dbeefd88cec42db09392ac7cb1e2c64689ca1fe63";

  var pubKey = PublicKey.fromCompressedHex(a1);

  var pubStr = pubKey.toHex();

  var res = '';

  for (var i in pubStr.split('')) {
    if (res.isEmpty) {
      res += i;
    } else {
      print("0x$res$i,");
      res = '';
    }
  }
  return;
  var a = [
    '0xd7',
    '0xfe',
    '0x9b',
    '0x49',
    '0xd0',
    '0x63',
    '0x1e',
    '0x36',
    '0x82',
    '0x8c',
    '0xbc',
    '0xc7',
    '0xf4',
    '0xaf',
    '0x8b',
    '0x29',
    '0x3e',
    '0x44',
    '0x3c',
    '0xa8',
    '0x40',
    '0xdf',
    '0xb8',
    '0x9a',
    '0xef',
    '0x4f',
    '0x4a',
    '0xb0',
    '0x5e',
    '0x1f',
    '0xb3',
    '0x07'
  ];

  List res1 = [];

  // for (var i in a) {
  //   res1.add('0x${i.toRadixString(16)}');
  // }

  var b = [
    219,
    86,
    255,
    221,
    1,
    108,
    158,
    88,
    159,
    227,
    15,
    28,
    27,
    232,
    191,
    6,
    255,
    56,
    104,
    34,
    146,
    165,
    41,
    15,
    20,
    168,
    254,
    196,
    65,
    19,
    208,
    73,
    106,
    171,
    167,
    33,
    80,
    121,
    156,
    168,
    35,
    240,
    17,
    48,
    183,
    27,
    250,
    98,
    8,
    97,
    24,
    160,
    82,
    116,
    119,
    72,
    177,
    58,
    71,
    64,
    79,
    232,
    70,
    170
  ];

  print(b.length);
  print(base64.encode(b));
}
