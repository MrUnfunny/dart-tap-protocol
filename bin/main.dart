import 'dart:convert';

import 'package:cbor/cbor.dart';

void main() {
  final cborRaw = [
    166,
    101,
    112,
    114,
    111,
    116,
    111,
    1,
    99,
    118,
    101,
    114,
    101,
    49,
    46,
    48,
    46,
    51,
    101,
    98,
    105,
    114,
    116,
    104,
    26,
    0,
    10,
    174,
    97,
    102,
    112,
    117,
    98,
    107,
    101,
    121,
    88,
    33,
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
    106,
    99,
    97,
    114,
    100,
    95,
    110,
    111,
    110,
    99,
    101,
    80,
    204,
    191,
    224,
    231,
    61,
    126,
    115,
    32,
    173,
    10,
    117,
    112,
    3,
    36,
    30,
    117,
    101,
    115,
    108,
    111,
    116,
    115,
    130,
    0,
    10
  ];
  final cborDecoded = cbor.decode(cborRaw);
  final cborObj = Map<String, dynamic>.from(cborDecoded.toObject() as Map);

  print(cborObj);
  // print(cborDecoded.toJson());

  print(utf8.encode("AzKDDjIJ6VCVetOWTCI_iPjfYdrS9xYIf1wzbaYzcqVu"));
}
