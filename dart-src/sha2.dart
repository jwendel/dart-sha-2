// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

part of mycrypto;


abstract class _SHA224_256Base extends _Hash32Base {
  
  _SHA224_256Base(int resultLengthInWords) 
    : _w = new List(16 * _BYTES_PER_32_WORD), super(16, 8, true, resultLengthInWords);
  
  // Table of round constants. First 32 bits of the fractional
  // parts of the cube roots of the first 64 prime numbers.
  static const List<int> _K =
      const [ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
              0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
              0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
              0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
              0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
              0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
              0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
              0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
              0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
              0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
              0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
              0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
              0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 ];
  
  // Helper functions as defined in http://tools.ietf.org/html/rfc6234
  _rotr32(n, x) => (x >> n) | ((x << (32 - n)) & _MASK_32);
  _ch(x, y, z) => (x & y) ^ ((~x & _MASK_32) & z);
  _maj(x, y, z) => (x & y) ^ (x & z) ^ (y & z);
  _bsig0(x) => _rotr32(2, x) ^ _rotr32(13, x) ^ _rotr32(22, x);
  _bsig1(x) => _rotr32(6, x) ^ _rotr32(11, x) ^ _rotr32(25, x);
  _ssig0(x) => _rotr32(7, x) ^ _rotr32(18, x) ^ (x >> 3);
  _ssig1(x) => _rotr32(17, x) ^ _rotr32(19, x) ^ (x >> 10);
  
  // Compute one iteration of the SHA256 algorithm with a chunk of
  // 16 32-bit pieces.
  void _updateHash(List<int> M) {
    assert(M.length == 16);

    // Prepare message schedule.
    var i = 0;
    for (; i < 16; i++) {
      _w[i] = M[i];
    }
    for (; i < 64; i++) {
      _w[i] = _add32(_add32(_ssig1(_w[i - 2]), _w[i - 7]),
                     _add32(_ssig0(_w[i - 15]), _w[i - 16]));
    }

    // Shuffle around the bits.
    var a = _h[0];
    var b = _h[1];
    var c = _h[2];
    var d = _h[3];
    var e = _h[4];
    var f = _h[5];
    var g = _h[6];
    var h = _h[7];

    for (var t = 0; t < 64; t++) {
      var t1 = _add32(_add32(h, _bsig1(e)),
                      _add32(_ch(e, f, g), _add32(_K[t], _w[t])));
      var t2 = _add32(_bsig0(a), _maj(a, b, c));
      h = g;
      g = f;
      f = e;
      e = _add32(d, t1);
      d = c;
      c = b;
      b = a;
      a = _add32(t1, t2);
    }

    // Update hash values after iteration.
    _h[0] = _add32(a, _h[0]);
    _h[1] = _add32(b, _h[1]);
    _h[2] = _add32(c, _h[2]);
    _h[3] = _add32(d, _h[3]);
    _h[4] = _add32(e, _h[4]);
    _h[5] = _add32(f, _h[5]);
    _h[6] = _add32(g, _h[6]);
    _h[7] = _add32(h, _h[7]);
  }
  
  List<int> _w;
}

class _SHA256 extends _SHA224_256Base implements SHA256 {

  _SHA256() : super(8) {
    // Initial value of the hash parts. First 32 bits of the fractional parts
    // of the square roots of the first 8 prime numbers.
    _h[0] = 0x6a09e667;
    _h[1] = 0xbb67ae85;
    _h[2] = 0x3c6ef372;
    _h[3] = 0xa54ff53a;
    _h[4] = 0x510e527f;
    _h[5] = 0x9b05688c;
    _h[6] = 0x1f83d9ab;
    _h[7] = 0x5be0cd19;
  }
  
  // Returns a new instance of this Hash.
  SHA256 newInstance() {
    return new SHA256();
  }
}

class _SHA224 extends _SHA224_256Base implements SHA224 {

  _SHA224() : super(7) {
    // Initial value of the hash parts. First 32 bits of the fractional parts
    // of the square roots of the first 8 prime numbers.
    _h[0] = 0xc1059ed8;
    _h[1] = 0x367cd507;
    _h[2] = 0x3070dd17;
    _h[3] = 0xf70e5939;
    _h[4] = 0xffc00b31;
    _h[5] = 0x68581511;
    _h[6] = 0x64f98fa7;
    _h[7] = 0xbefa4fa4;
  }
  
  // Returns a new instance of this Hash.
  SHA224 newInstance() {
    return new SHA224();
  }
}



abstract class _SHA384_512Base extends _Hash64Base {
  
  _SHA384_512Base(int resultLengthInWords) 
      : _w = new List(16 * _BYTES_PER_64_WORD), super(16, 8, resultLengthInWords);
  
  // Table of round constants. First 32 bits of the fractional
  // parts of the cube roots of the first 64 prime numbers.
  static const List<int> _K =
      const [ 
              0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
              0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
              0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
              0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
              0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
              0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
              0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
              0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
              0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
              0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
              0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
              0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
              0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
              0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
              0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
              0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
              0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
              0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
              0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
              0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817 ];
  
  
  // Helper functions as defined in http://tools.ietf.org/html/rfc6234
  _rotr64(n, x) => (x >> n) | ((x << (64 - n)) & _MASK_64);
  _ch(x, y, z) => (x & y) ^ ((~x & _MASK_64) & z);
  _maj(x, y, z) => (x & y) ^ (x & z) ^ (y & z);
  _bsig0(x) => _rotr64(28, x) ^ _rotr64(34, x) ^ _rotr64(39, x);
  _bsig1(x) => _rotr64(14, x) ^ _rotr64(18, x) ^ _rotr64(41, x);
  _ssig0(x) => _rotr64(1, x) ^ _rotr64(8, x) ^ (x >> 7);
  _ssig1(x) => _rotr64(19, x) ^ _rotr64(61, x) ^ (x >> 6);
  
  // Compute one iteration of the SHA256 algorithm with a chunk of
  // 16 32-bit pieces.
  void _updateHash(List<int> M) {
    assert(M.length == 16);

    // Prepare message schedule.
    var i = 0;
    for (; i < 16; i++) {
      _w[i] = M[i];
    }
    for (; i < 80; i++) {
      _w[i] = _add64(_add64(_ssig1(_w[i - 2]), _w[i - 7]),
                     _add64(_ssig0(_w[i - 15]), _w[i - 16]));
    }

    // Shuffle around the bits.
    var a = _h[0];
    var b = _h[1];
    var c = _h[2];
    var d = _h[3];
    var e = _h[4];
    var f = _h[5];
    var g = _h[6];
    var h = _h[7];

    for (var t = 0; t < 80; t++) {
      var t1 = _add64(_add64(h, _bsig1(e)),
                      _add64(_ch(e, f, g), _add64(_K[t], _w[t])));
      var t2 = _add64(_bsig0(a), _maj(a, b, c));
      h = g;
      g = f;
      f = e;
      e = _add64(d, t1);
      d = c;
      c = b;
      b = a;
      a = _add64(t1, t2);
    }

    // Update hash values after iteration.
    _h[0] = _add64(a, _h[0]);
    _h[1] = _add64(b, _h[1]);
    _h[2] = _add64(c, _h[2]);
    _h[3] = _add64(d, _h[3]);
    _h[4] = _add64(e, _h[4]);
    _h[5] = _add64(f, _h[5]);
    _h[6] = _add64(g, _h[6]);
    _h[7] = _add64(h, _h[7]);
  }
  
  List<int> _w;
}

class _SHA512 extends _SHA384_512Base implements SHA512 {

  _SHA512() : super(8) {
    // Initial value of the hash parts. First 32 bits of the fractional parts
    // of the square roots of the first 8 prime numbers.
    _h[0] = 0x6a09e667f3bcc908;
    _h[1] = 0xbb67ae8584caa73b;
    _h[2] = 0x3c6ef372fe94f82b;
    _h[3] = 0xa54ff53a5f1d36f1;
    _h[4] = 0x510e527fade682d1;
    _h[5] = 0x9b05688c2b3e6c1f;
    _h[6] = 0x1f83d9abfb41bd6b;
    _h[7] = 0x5be0cd19137e2179;
  }
  
  // Returns a new instance of this Hash.
  SHA512 newInstance() {
    return new SHA512();
  }
}

class _SHA384 extends _SHA384_512Base implements SHA384 {

  _SHA384() : super(6) {
    // Initial value of the hash parts. First 32 bits of the fractional parts
    // of the square roots of the first 8 prime numbers.
    _h[0] = 0xcbbb9d5dc1059ed8;
    _h[1] = 0x629a292a367cd507;
    _h[2] = 0x9159015a3070dd17;
    _h[3] = 0x152fecd8f70e5939;
    _h[4] = 0x67332667ffc00b31;
    _h[5] = 0x8eb44a8768581511;
    _h[6] = 0xdb0c2e0d64f98fa7;
    _h[7] = 0x47b5481dbefa4fa4;
  }
  
  // Returns a new instance of this Hash.
  SHA384 newInstance() {
    return new SHA384();
  }
}
