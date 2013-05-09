// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

part of crypto;

// Constants.
const _MASK_8 = 0xff;
const _BITS_PER_BYTE = 8;
const _BYTES_PER_WORD_32 = 4;
const _BYTES_PER_WORD_64 = 8;

const _MASK_32 = 0xffffffff;
const _MASK_64 = 0xffffffffffffffff;

// Helper functions used by more than one hasher.

// Rotate left limiting to unsigned 32-bit values.
int _rotl32(int val, int shift) {
  var mod_shift = shift & 31;
  return ((val << mod_shift) & _MASK_32) |
      ((val & _MASK_32) >> (32 - mod_shift));
}

// Base class encapsulating common behavior for cryptographic hash
// functions.
abstract class _Hash32Base implements Hash {
  _Hash32Base(int this._chunkSizeInWords,
            int this._digestSizeInWords,
            bool this._bigEndianWords,
            int this._resultLengthInWords)
      : _pendingData = [] {
    _currentChunk = new List(_chunkSizeInWords);
    _h = new List(_digestSizeInWords);
  }

  // Update the hasher with more data.
  add(List<int> data) {
    if (_digestCalled) {
      throw new HashException(
          'Hash update method called after digest was retrieved');
    }
    _lengthInBytes += data.length;
    _pendingData.addAll(data);
    _iterate();
  }

  // Finish the hash computation and return the digest string.
  List<int> close() {
    if (_digestCalled) {
      return _resultAsBytes();
    }
    _digestCalled = true;
    _finalizeData();
    _iterate();
    assert(_pendingData.length == 0);
    return _resultAsBytes();
  }

  // Returns the block size of the hash in bytes.
  int get blockSize {
    return _chunkSizeInWords * _BYTES_PER_WORD_32;
  }

  // Create a fresh instance of this Hash.
  newInstance();

  // One round of the hash computation.
  _updateHash(List<int> m);

  // Helper methods.
  _add32(x, y) => (x + y) & _MASK_32;
  _roundUp(val, n) => (val + n - 1) & -n;

  // Compute the final result as a list of bytes from the hash words.
  _resultAsBytes() {
    var result = new List(_resultLengthInWords * _BYTES_PER_WORD_32);
    for (var i = 0; i < _resultLengthInWords; i++) {
      int start = i * _BYTES_PER_WORD_32;
      result.setRange(start, start+_BYTES_PER_WORD_32, _wordToBytes(_h[i]));
    }
    return result;
  }

  // Converts a list of bytes to a chunk of 32-bit words.
  _bytesToChunk(List<int> data, int dataIndex) {
    assert((data.length - dataIndex) >= (_chunkSizeInWords * _BYTES_PER_WORD_32));

    for (var wordIndex = 0; wordIndex < _chunkSizeInWords; wordIndex++) {
      var w3 = _bigEndianWords ? data[dataIndex] : data[dataIndex + 3];
      var w2 = _bigEndianWords ? data[dataIndex + 1] : data[dataIndex + 2];
      var w1 = _bigEndianWords ? data[dataIndex + 2] : data[dataIndex + 1];
      var w0 = _bigEndianWords ? data[dataIndex + 3] : data[dataIndex];
      dataIndex += 4;
      var word = (w3 & 0xff) << 24;
      word |= (w2 & _MASK_8) << 16;
      word |= (w1 & _MASK_8) << 8;
      word |= (w0 & _MASK_8);
      _currentChunk[wordIndex] = word;
    }
  }

  // Convert a 32-bit word to four bytes.
  _wordToBytes(int word) {
    List<int> bytes = new List(_BYTES_PER_WORD_32);
    bytes[0] = (word >> (_bigEndianWords ? 24 : 0)) & _MASK_8;
    bytes[1] = (word >> (_bigEndianWords ? 16 : 8)) & _MASK_8;
    bytes[2] = (word >> (_bigEndianWords ? 8 : 16)) & _MASK_8;
    bytes[3] = (word >> (_bigEndianWords ? 0 : 24)) & _MASK_8;
    return bytes;
  }

  // Iterate through data updating the hash computation for each
  // chunk.
  _iterate() {
    var len = _pendingData.length;
    var chunkSizeInBytes = _chunkSizeInWords * _BYTES_PER_WORD_32;
    if (len >= chunkSizeInBytes) {
      var index = 0;
      for (; (len - index) >= chunkSizeInBytes; index += chunkSizeInBytes) {
        _bytesToChunk(_pendingData, index);
        _updateHash(_currentChunk);
      }
      _pendingData = _pendingData.sublist(index, len);
    }
  }

  // Finalize the data. Add a 1 bit to the end of the message. Expand with
  // 0 bits and add the length of the message.
  _finalizeData() {
    _pendingData.add(0x80);
    var contentsLength = _lengthInBytes + 9;
    var chunkSizeInBytes = _chunkSizeInWords * _BYTES_PER_WORD_32;
    var finalizedLength = _roundUp(contentsLength, chunkSizeInBytes);
    var zeroPadding = finalizedLength - contentsLength;
    for (var i = 0; i < zeroPadding; i++) {
      _pendingData.add(0);
    }
    var lengthInBits = _lengthInBytes * _BITS_PER_BYTE;
    assert(lengthInBits < pow(2, 32));
    if (_bigEndianWords) {
      _pendingData.addAll(_wordToBytes(0));
      _pendingData.addAll(_wordToBytes(lengthInBits & _MASK_32));
    } else {
      _pendingData.addAll(_wordToBytes(lengthInBits & _MASK_32));
      _pendingData.addAll(_wordToBytes(0));
    }
  }

  // Hasher state.
  final int _chunkSizeInWords;
  final int _digestSizeInWords;
  final bool _bigEndianWords;
  int _lengthInBytes = 0;
  final int _resultLengthInWords;
  List<int> _pendingData;
  List<int> _currentChunk;
  List<int> _h;
  bool _digestCalled = false;
}


abstract class _Hash64Base implements Hash {
  _Hash64Base(int this._chunkSizeInWords,
            int this._digestSizeInWords,
            int this._resultLengthInWords)
      : _pendingData = [] {
    _currentChunk = new List(_chunkSizeInWords);
    _h = new List(_digestSizeInWords);
  }

  // Update the hasher with more data.
  add(List<int> data) {
    if (_digestCalled) {
      throw new HashException(
          'Hash update method called after digest was retrieved');
    }
    _lengthInBytes += data.length;
    _pendingData.addAll(data);
    _iterate();
  }

  // Finish the hash computation and return the digest string.
  List<int> close() {
    if (_digestCalled) {
      return _resultAsBytes();
    }
    _digestCalled = true;
    _finalizeData();
    _iterate();
    assert(_pendingData.length == 0);
    return _resultAsBytes();
  }

  // Returns the block size of the hash in bytes.
  int get blockSize {
    return _chunkSizeInWords * _BYTES_PER_WORD_64;
  }

  // Create a fresh instance of this Hash.
  newInstance();

  // One round of the hash computation.
  _updateHash(List<int> m);

  // Helper methods.
  _add64(x, y) => (x + y) & _MASK_64;
  _roundUp(val, n) => (val + n - 1) & -n;

  // Compute the final result as a list of bytes from the hash words.
  _resultAsBytes() {
    var result = new List(_resultLengthInWords * _BYTES_PER_WORD_64);
    for (var i = 0; i < _resultLengthInWords; i++) {
      int start = i * _BYTES_PER_WORD_64;
      result.setRange(start, start+_BYTES_PER_WORD_64, _wordToBytes(_h[i]));
    }
    return result;
  }

  // Converts a list of bytes to a chunk of 64-bit words.
  _bytesToChunk(List<int> data, int dataIndex) {
    assert((data.length - dataIndex) >= (_chunkSizeInWords * _BYTES_PER_WORD_64));

    for (var wordIndex = 0; wordIndex < _chunkSizeInWords; wordIndex++) {
      var w7 = data[dataIndex];
      var w6 = data[dataIndex + 1];
      var w5 = data[dataIndex + 2];
      var w4 = data[dataIndex + 3];
      var w3 = data[dataIndex + 4];
      var w2 = data[dataIndex + 5];
      var w1 = data[dataIndex + 6];
      var w0 = data[dataIndex + 7];
      dataIndex += 8;
      var word = (w7 & 0xff) << 56;
      word |= (w6 & _MASK_8) << 48;
      word |= (w5 & _MASK_8) << 40;
      word |= (w4 & _MASK_8) << 32;
      word |= (w3 & _MASK_8) << 24;
      word |= (w2 & _MASK_8) << 16;
      word |= (w1 & _MASK_8) << 8;
      word |= (w0 & _MASK_8);
      _currentChunk[wordIndex] = word;
    }
  }

  // Convert a 64-bit word to four bytes.
  _wordToBytes(int word) {
    List<int> bytes = new List(_BYTES_PER_WORD_64);
    bytes[0] = (word >> (56)) & _MASK_8;
    bytes[1] = (word >> (48)) & _MASK_8;
    bytes[2] = (word >> (40)) & _MASK_8;
    bytes[3] = (word >> (32)) & _MASK_8;
    bytes[4] = (word >> (24)) & _MASK_8;
    bytes[5] = (word >> (16)) & _MASK_8;
    bytes[6] = (word >> (8)) & _MASK_8;
    bytes[7] = (word >> (0)) & _MASK_8;
    return bytes;
  }

  // Iterate through data updating the hash computation for each
  // chunk.
  _iterate() {
    var len = _pendingData.length;
    var chunkSizeInBytes = _chunkSizeInWords * _BYTES_PER_WORD_64;
    if (len >= chunkSizeInBytes) {
      var index = 0;
      for (; (len - index) >= chunkSizeInBytes; index += chunkSizeInBytes) {
        _bytesToChunk(_pendingData, index);
        _updateHash(_currentChunk);
      }
      _pendingData = _pendingData.sublist(index, len);
    }
  }

  // Finalize the data. Add a 1 bit to the end of the message. Expand with
  // 0 bits and add the length of the message.
  _finalizeData() {
    _pendingData.add(0x80);
    var contentsLength = _lengthInBytes + 17;
    var chunkSizeInBytes = _chunkSizeInWords * _BYTES_PER_WORD_64;
    var finalizedLength = _roundUp(contentsLength, chunkSizeInBytes);
    var zeroPadding = finalizedLength - contentsLength;
    for (var i = 0; i < zeroPadding; i++) {
      _pendingData.add(0);
    }
    var lengthInBits = _lengthInBytes * _BITS_PER_BYTE;
    assert(lengthInBits < pow(2, 64));
    _pendingData.addAll(_wordToBytes(0));
    _pendingData.addAll(_wordToBytes(lengthInBits & _MASK_64));
  }

  // Hasher state.
  final int _chunkSizeInWords;
  final int _digestSizeInWords;
  int _lengthInBytes = 0;
  final int _resultLengthInWords;
  List<int> _pendingData;
  List<int> _currentChunk;
  List<int> _h;
  bool _digestCalled = false;
}
