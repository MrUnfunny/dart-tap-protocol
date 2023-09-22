import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:fast_base58/fast_base58.dart';
import 'package:hex/hex.dart';
import 'package:tap_protocol/src/compat.dart';
import 'package:tap_protocol/src/utils.dart';
import 'package:cbor/cbor.dart';

class CkTapCard {
  Uint8List? cardNonce;
  Uint8List? cardPubKey;
  String? cardIdent;
  String? appletVersion;
  int? birthHeight;
  bool? isTestnet;
  int? authDelay;
  bool? isTapSigner;
  String? path;
  int? numBackups;
  String? error;

  Future<Map<String, dynamic>> send({
    required String cmd,
    Map<String, dynamic>? args,
  }) async {
    final host = InternetAddress(
      '/tmp/ecard-pipe',
      type: InternetAddressType.unix,
    );

    print("+++++++++++++++++++++++++++");
    print('sending data:\n');
    print({
      'cmd': cmd,
      ...(args ?? {}),
    });
    print("+++++++++++++++++++++++++++\n\n");

    final x = cbor.encode(
      (args == null)
          ? CborValue({
              'cmd': cmd,
            })
          : CborValue({
              'cmd': cmd,
              ...args,
            }),
    );

    final socket = await Socket.connect(host, 0);

    socket.add(x);

    final cborRes = await socket.first;
    var response = cborDecode(cborRes).toObject() as Map;

    socket.close();
    print('closed ${cborDecode(cborRes)}\n\n\n');

    if (response["card_nonce"] != null) {
      cardNonce = Uint8List.fromList(response["card_nonce"]);
    }
    if (response["auth_delay"] != null) {
      authDelay = response["auth_delay"];
    }
    if (response["Exception"] != null) {
      error = response["Exception"];
    }

    return Map<String, dynamic>.from(response);
  }

  Future<void> firstLook() async {
    // Call this at end of __init__ to load up details from card
    // - can be called multiple times
    final resp = await send(cmd: "status");

    if (resp["Exception"] != null) {
      throw Exception("Early filure");
    }
    if (resp["proto"] != 1) {
      throw Exception("Unknown card protocol version");
    }
    if (resp["tampered"] != null) {
      throw Exception("WARNING: Card has set tampered flag!");
    }

    cardPubKey = Uint8List.fromList(resp["pubkey"]);
    cardIdent = cardPubKeyToIdent(cardPubKey!);
    appletVersion = resp["ver"];
    birthHeight = resp["birth"];
    isTestnet = resp["testnet"] ?? false;
    authDelay = resp["auth_delay"] ?? 0;
    isTapSigner = resp["tapsigner"] != 0;
    path = resp["path"] != null ? path2str(List.from(resp["path"])) : null;
    numBackups = resp["num_backups"] ?? "NA";
    cardNonce = Uint8List.fromList(resp["card_nonce"]);
    // final [active_slot, num_slots] = resp["slots"] || [0, 1];
    // activeSlot = active_slot;
    // numSlots = num_slots;
  }

  Future<Map<String, dynamic>> sendAuth({
    required String cmd,
    String? cvc,
    Map<String, dynamic>? args,
  }) async {
    // Take CVC and do ECDH crypto and provide the CVC in encrypted form
    // - returns session key and usual auth arguments needed
    // - skip if CVC is null and just do normal stuff (optional auth on some cmds)
    // - for commands w/ encrypted arguments, you must provide to this function
    Uint8List sessionKey = Uint8List(33);
    Map<String, dynamic> authArgs;

    args = args ?? {};

    if (cvc != null) {
      final xcvcRes = calcXcvc(
        cmd,
        cardNonce!,
        cardPubKey!,
        cvc,
      );
      sessionKey = Uint8List.fromList(xcvcRes["sk"]);
      authArgs = xcvcRes["ag"];
      args = {...args, ...authArgs};
    }
    // A few commands take an encrypted argument (most are returning encrypted
    // results) and the caller didn't know the session key yet. So xor it for them.
    if (cmd == "sign") {
      args["digest"] = xorBytes(args["digest"], sessionKey);
    } else if (cmd == "change") {
      args["data"] = xorBytes(
        args["data"],
        sessionKey.sublist(0, args["data"].length),
      );
    }
    final resp = await send(cmd: cmd, args: args);
    return {
      "sessionKey": sessionKey,
      ...resp,
    };
  }

  Future<String> getXfp({required String cvc}) async {
    // fetch master xpub, take pubkey from that and calc XFP
    if (isTapSigner != true) {
      throw Exception("Not a Tapsigner");
    }
    final response = await sendAuth(
      cmd: "xpub",
      cvc: cvc,
      args: {
        "master": true,
      },
    );
    final xpub = Uint8List.fromList(response["xpub"]).sublist(45, 78);

    final hashRes = hash160(xpub);

    return HEX.encode(hashRes);
  }

  Future<String> getXpub({
    required String cvc,
    bool master = false,
  }) async {
    final response = await sendAuth(
      cmd: "xpub",
      cvc: cvc,
      args: {
        "master": master,
      },
    );

    final xpub = List<int>.from(response["xpub"]);

    final xpubString = Base58Encode([
      ...xpub,
      ...sha256.convert(sha256.convert(xpub).bytes).bytes.sublist(0, 4)
    ]);

    return xpubString;
  }

  Future<Uint8List> makeBackup({required String cvc}) async {
    // read the backup file; gives ~100 bytes to be kept long term
    if (isTapSigner != true) {
      throw Exception("not a Tapsigner");
    }

    final response = await sendAuth(
      cmd: "backup",
      cvc: cvc,
    );

    return Uint8List.fromList(response["data"]);
  }

  void certificateCheck() async {
    final status = await send(cmd: 'status');
    final certs = await send(cmd: 'certs');

    final nonce = pickNonce();

    final check = await send(
      cmd: 'check',
      args: {'nonce': nonce},
    );

    final verified = verifyCerts(
      statusRes: status,
      checkRes: check,
      certsRes: certs,
      nonce: nonce,
    );

    if (verified) {
      print("Certificate is valid");
    } else {
      throw Exception("Certicate Validation Failed! Card is Counterfeit");
    }
  }

  Future<Map> changeCvc({
    required String oldCvc,
    required String newCvc,
  }) async {
    if (newCvc.length < 6 || oldCvc.length > 32) {
      throw Exception("CVC must be 6 to 32 characters long");
    }
    return sendAuth(
      cmd: "change",
      cvc: oldCvc,
      args: {
        "data": utf8.encode(newCvc),
      },
    );
  }

  Future<Map<String, dynamic>> signDigest({
    required String cvc,
    required String slot,
    required Uint8List digest,
    String? subpath,
  }) async {
    /*
        Sign 32 bytes digest and return 65 bytes long recoverable signature.

        Uses derivation path based on current set derivation on card plus optional
        subpath parameter which if provided, will be added to card derivation path.
        Subpath can only be of length 2 and non-hardened components only.

        Returns non-deterministic recoverable signature (header[1b], r[32b], s[32b])
        */
    //  Expects the digest to be 32 bit Buffer and parsed by the wallet
    if (digest.length != 32) {
      throw Exception("Digest must be exactly 32 bytes");
    }
    if ((isTapSigner != true) && (subpath != null)) {
      throw Exception("Cannot use 'subpath' option for SATSCARD");
    }
    // subpath validation
    final intPath = subpath != null ? str2path(subpath) : <int>[];
    if (intPath.length > 2) {
      throw Exception("Length of path $subpath greater than 2");
    }
    if (!noneHardened(intPath)) {
      throw Exception("Subpath $subpath contains hardened components");
    }
    if (isTapSigner!) {
      slot = '0';
    }
    for (var i = 0; i < 4; i++) {
      try {
        final signResponse = await sendAuth(
          cmd: "sign",
          cvc: cvc,
          args: {
            "slot": slot,
            "digest": digest,
            "subpath": isTapSigner! ? intPath : null,
          },
        );

        final sessionKey = signResponse["sessionKey"];

        final expectPub = signResponse["pubkey"];
        final sig = signResponse["sig"];

        if (!ctSigVerify(sig: sig, msgDigest: digest, pubKey: expectPub)) {
          continue;
        }

        // const rec_sig = make_recoverable_sig(
        //     digest, sig, null, expect_pub, this.is_testnet);

        return signResponse;
        //TODO: return proper data
        // return rec_sig;
      } catch (e) {
        //TODO: implement
        // if (Exception.code === 205) {
        //   // unlucky number
        //   // status to update card nonce
        //   await this.send("status");
        //   continue;
        // }
        // throw Exception(Exception);
      }
    }
    // probability that we get here is very close to zero
    const msg = "Failed to sign digest after 5 retries. Try again.";
    throw Exception("500 on sign: $msg");
  }

  Future<void> setup({
    required String cvc,
    Uint8List? chainCode,
    required bool newChainCode,
  }) async {
    var target = 0;
    if (chainCode == null) {
      newChainCode = true;
    }

    Map<String, dynamic> args = {"slot": target};

    if (newChainCode) {
      args["chain_code"] =
          sha256.convert(sha256.convert(generateRandomBytes(128)).bytes).bytes;
    } else if (chainCode != null) {
      try {
        if (chainCode.length != 32) {
          throw Exception("Chain code must be exactly 32 bytes");
        }
      } catch (e) {
        throw Exception("Need 64 hex digits (32 bytes) for chain code.");
      }
      args["chain_code"] = chainCode;
    } else if (target == 0) {
      // not expected case since factory setup on slot zero
      throw Exception("Chain code required for slot zero setup");
    }

    try {
      await sendAuth(
        cmd: "new",
        cvc: cvc,
        args: args,
      );
      print("TAPSIGNER ready for use");
    } catch (e) {
      print(e);
      print("card failed to setup");
    }
  }

  Future<Map<String, dynamic>> wait(String cvc) async {
    return await send(
      cmd: "wait",
    );
  }

  Future<Map<String, dynamic>> read(String cvc) async {
    return await sendAuth(
      cmd: "read",
      cvc: cvc,
      args: {
        'nonce': pickNonce(),
      },
    );
  }
}
