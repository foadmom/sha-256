// =================================================================================
// extracts from fips180-3_SHS-final document. definitions of symboles
// =================================================================================
// ∧ Bitwise AND operation.
// ∨ Bitwise OR (“inclusive-OR”) operation.
// ⊕ Bitwise XOR (“exclusive-OR”) operation.
// ¬ Bitwise complement operation.
// + Addition modulo 2 w .
// << Left-shift operation,
//		where x << n is obtained by discarding the left-most n
// 		bits of the word x and then padding the result with n zeroes on the right.
// >> Right-shift operation,
//		where x >> n is obtained by discarding the right-
// 		most n bits of the word x and then padding the result with n zeroes on the
// 		left.
//
// The following operations are used in the secure hash algorithm specifications:
// - ROTL n (x):
//		 The rotate left (circular left shift) operation, where x is a w -bit word and n
// 		is an integer with 0 ≤ n < w , is defined by ROTL n ( x )=( x << n ) ∨
// 		( x >> w - n ).
// - ROTR n (x):
//		The rotate right (circular right shift) operation, where x is a w -bit word
// 		and n is an integer with 0 ≤ n < w , is defined by ROTR n ( x )=( x >> n ) ∨
// 		( x << w - n ).
// 		5SHR n (x)
// - SHR n (x):
//		The right shift operation, where x is a w -bit word and n is an integer with 0
// 		≤ n < w , is defined by SHR n ( x )= x >> n .
//
// =====================================================================================================================
// comments below are courtesy of https://qvault.io/2020/07/08/how-sha-2-works-step-by-step-sha-256/
// =====================================================================================================================
// Note 1: All variables are 32 bit unsigned integers and addition is calculated modulo 232
// Note 2: For each round, there is one round constant k[i] and one entry in the message schedule array w[i], 0 ≤ i ≤ 63
// Note 3: The compression function uses 8 working variables, a through h
// Note 4: Big-endian convention is used when expressing the constants in this pseudocode,
//     and when parsing message block data from bytes to words, for example,
//     the first word of the input message "abc" after padding is 0x61626380
//
// Initialize hash values:
// (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
// h[0] := 0x6a09e667
// h[1] := 0xbb67ae85
// h[2] := 0x3c6ef372
// h[3] := 0xa54ff53a
// h[4] := 0x510e527f
// h[5] := 0x9b05688c
// h[6] := 0x1f83d9ab
// h[7] := 0x5be0cd19
//
// Initialize array of round constants:
// (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
// k[0..63] :=
//    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
//    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
//    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
//    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
//    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
//    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
//    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
//    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
//
// Pre-processing (Padding):
// begin with the original message of length L bits
// append a single '1' bit
// append K '0' bits, where K is the minimum number >= 0 such that L + 1 + K + 64 is a multiple of 512
// append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
//
// Process the message in successive 512-bit chunks:
// break message into 512-bit chunks
// for each chunk
//     create a 64-entry message schedule array w[0..63] of 32-bit words
//     (The initial values in w[0..63] don't matter, so many implementations zero them here)
//     copy chunk into first 16 words w[0..15] of the message schedule array
//
//     Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
//     for i from 16 to 63
//         s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)
//         s1 := (w[i- 2] rightrotate 17) xor (w[i- 2] rightrotate 19) xor (w[i- 2] rightshift 10)
//         w[i] := w[i-16] + s0 + w[i-7] + s1
//
//     Initialize working variables to current hash value:
//     a := h[0]
//     b := h[1]
//     c := h[2]
//     d := h[3]
//     e := h[4]
//     f := h[5]
//     g := h[6]
//     h := h[7]
//
//     Compression function main loop:
//     for i from 0 to 63
//         S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
//         ch := (e and f) xor ((not e) and g)
//         temp1 := h + S1 + ch + k[i] + w[i]
//         S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
//         maj := (a and b) xor (a and c) xor (b and c)
//         temp2 := S0 + maj
//
//         h := g
//         g := f
//         f := e
//         e := d + temp1
//         d := c
//         c := b
//         b := a
//         a := temp1 + temp2
//
//     Add the compressed chunk to the current hash value:
//     h[0] := h[0] + a
//     h[1] := h[1] + b
//     h[2] := h[2] + c
//     h[3] := h[3] + d
//     h[4] := h[4] + e
//     h[5] := h[5] + f
//     h[6] := h[6] + g
//     h[7] := h[7] + h
//
// Produce the final hash value (big-endian):
// digest := hash := h[0] append h[1] append h[2] append h[3] append h[4] append h[5] append h[6] append h[7]
// =====================================================================================================================
// =====================================================================================================================
// =====================================================================================================================

package sha_256

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

// type schedule uint32;
//type schedule [64]uint32;

// define the constants:
var H0 uint32 = 0x6a09e667;
var H1 uint32 = 0xbb67ae85;
var H2 uint32 = 0x3c6ef372;
var H3 uint32 = 0xa54ff53a;
var H4 uint32 = 0x510e527f;
var H5 uint32 = 0x9b05688c;
var H6 uint32 = 0x1f83d9ab;
var H7 uint32 = 0x5be0cd19;

var h []uint32 = []uint32 {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};

// sha-224 and sha-256 contstants:
var K []uint32 = []uint32 {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2  };

type params struct {
	input		[]byte;
	buffer  	[]byte;
	blocks  	[][]byte;
	schedules	[][]uint32;
	bOutput 	[]byte;
	sOutput 	string;
	h       	[]uint32;
	K			[]uint32;
}

// ==================================================================
// ==================================================================
// ==================================================================
// ==================================================================
// ==================================================================
// func main () {
// 	p := fmt.Println;
// 	p ("started");
// //	var _testString string = "Note 2: For each round, there is one round constant k[i] and one entry in the message schedule array w[i], 0 ≤ i ≤ 63";
// 	var _testString string = "abc";
// //	fmt.Printf ("testString = %s\nand the length is = %d\n", _testString, len(_testString));
// 	process ([]byte (_testString));

// }



func Sha_256 (input []byte) string {
	var _p *params = initialise (input);
//	 h = []uint32 {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
	_err := padMessageForSHA256 (_p);
	if (_err == nil) {_err = breakIntoBlocks (_p);}
	if (_err == nil) {_err = createScheduleArray(_p);}
	compression (_p);
//	fmt.Printf ("the final hash    %x\n", _finalHash);

	return _p.sOutput;
}

func initialise (input []byte) *params {
	var _p  params;
	_p.input  = input;
	_p.buffer = input;
	_p.h = []uint32 {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
	_p.K = K;
	return &_p;
}

func padMessageForSHA256 (p *params) error {
	var _err error;
	if (p.input == nil || len(p.input) < 1) {
		_err = errors.New ("input buffer is empty or nil");
	} else {
		var _lenInBytes int = len (p.input);

		// no of bytes to be added is calculated by bytes needed to make
		// the length a multiple of 512 bits (64 bytes) less the first byte
		// which is b10000000 and the last 8 bytes which is the length of 
		// the original message
		var _bytesToBeAdded int = 56-(_lenInBytes % 64)-1;
		if (_bytesToBeAdded < 0) {
			_bytesToBeAdded = _bytesToBeAdded + 64;
		}

		// first byte of the padding is 0x80
		p.buffer = append (p.buffer, 0x80); 

		// create an 8 byte slice of the original message length
		var _lenInfo []byte = make([]byte, 8);
		binary.BigEndian.PutUint64 (_lenInfo, uint64 (_lenInBytes)*8);
		
		// pad the rest of the buffer with 0s
		for _index:=0; _index<_bytesToBeAdded; _index++ {
			p.buffer = append (p.buffer, byte(0));
		}
		// and add the 8 byte length to the end
		p.buffer = append (p.buffer, _lenInfo...);
	}
	return _err;
}


func breakIntoBlocks (p *params) error {
	var _inLen  int = len (p.buffer);
	var _err    error = nil;
	var _numberOfBlocks int = _inLen / 64;
	var _blocks [][]byte = make ([][]byte, _numberOfBlocks);

	if (_inLen % 64 == 0) {
		for _index := 0; _index < _numberOfBlocks; _index++ {
			_i1 := _index*64;
			_i2 := (_index+1)*64;
			_blocks [_index] = p.buffer [(_i1) : (_i2) ];
		}
		p.blocks = _blocks;
	} else {
		_err = errors.New ("message is not padded correctly.");
	}
	return _err;
}



func createScheduleArray (p *params) error {

	var _noOfBlocks int = len(p.blocks);
	p.schedules = make ([][]uint32, _noOfBlocks);
	for j:=0; j<_noOfBlocks; j++ {
		var _schedule []uint32 = make ([]uint32, 64);
		// copy the message block into the first 16 schedules
		for i:=0; i<16; i++ {
			var _wordByte []byte = p.blocks [j][(i*4):((i*4)+4)]
			_schedule [i] = binary.BigEndian.Uint32 (_wordByte);
		}
		for i:=16; i<64; i++ {
			_schedule [i] = calculateWi_16_63 (i, _schedule)
		}
		p.schedules [j] = _schedule;
	}

	return nil;
}

func compression (p *params) error {
//	var _finalHash []byte;
	var _a, _b, _c, _d, _e, _f, _g, _h uint32;

	for j :=0; j < len(p.schedules); j++ {
		_a = p.h[0]; 	_b = p.h[1]; 	_c = p.h[2]; 	_d = p.h[3];
		_e = p.h[4]; 	_f = p.h[5]; 	_g = p.h[6]; 	_h = p.h[7];
			w := p.schedules [j];
		for i :=0; i<64; i++ {
			var _sig1 uint32 = sigma1 (_e);
			var _ch uint32 = ch (_e,_f,_g);
			var _temp1 uint32 = _h + _sig1 + _ch +  p.K[i] + w[i];
			var _sig0 uint32 = sigma0 (_a);
			var _maj uint32 = maj (_a,_b,_c);
			var _temp2 uint32 = _sig0 + _maj;

		    _h = _g
		    _g = _f
		    _f = _e
		    _e = _d + _temp1
		    _d = _c
		    _c = _b
		    _b = _a
		    _a = _temp1 + _temp2

		}
		p.h[0] = p.h[0] + _a
		p.h[1] = p.h[1] + _b
		p.h[2] = p.h[2] + _c
		p.h[3] = p.h[3] + _d
		p.h[4] = p.h[4] + _e
		p.h[5] = p.h[5] + _f
		p.h[6] = p.h[6] + _g
		p.h[7] = p.h[7] + _h
	}
	var _4bytes []byte = make ([]byte,4);
	for _hashIndex := 0; _hashIndex<8; _hashIndex++ {
		binary.BigEndian.PutUint32 (_4bytes, p.h[_hashIndex]);
		p.bOutput = append (p.bOutput, _4bytes...);
	}
	p.sOutput = encodeBcd (p.bOutput);
	return nil;
}


// ==================================================================
// bitwise operations
// ==================================================================
var uint32_max uint32 = 0xffffffff;
func additionMod2w_32 (x, y uint32) uint32 {
	return ((x+y) % uint32_max);
}

func shiftRight_32 (in uint32, shiftCount int) uint32 {
	return (in >> uint(shiftCount));
}

func shiftLeft_32 (in uint32, shiftCount int) uint32 {
	return (in << uint(shiftCount));
}
func rotateRight_32 (in uint32, rotateCount int) uint32 {
	return bits.RotateLeft32 (in, -1*rotateCount);
}

func rotateLeft_32 (in uint32, rotateCount int) uint32 {
	return bits.RotateLeft32 (in, rotateCount);
}

func NOT (word uint32) uint32 {
	return (word ^ 0xffffffff);
}

// ==================================================================
// ==================================================================
// ==================================================================
// ==================================================================
// based on the algorithms specified in 
// https://en.wikipedia.org/wiki/SHA-2
// ==================================================================
func ch (e, f, g uint32) uint32 {
	return (e & f) ^ (NOT(e) & g);
}

func maj (a,b,c uint32) uint32 {
	return (a & b) ^ (a & c) ^ (b & c);
}

func sigma0 (a uint32) uint32 {
	return (rotateRight_32 (a, 2)) ^ (rotateRight_32 (a, 13)) ^ (rotateRight_32 (a, 22));
}

func sigma1 (e uint32) uint32 {
	return (rotateRight_32 (e, 6)) ^ (rotateRight_32 (e, 11)) ^ (rotateRight_32 (e, 25))
}

func s0 (w uint32) uint32 {
	return (rotateRight_32 (w, 7) ^ rotateRight_32 (w, 18) ^ shiftRight_32 (w, 3));
}

func s1 (w uint32) uint32 {
	return (rotateRight_32 (w, 17) ^ rotateRight_32 (w, 19) ^ shiftRight_32 (w, 10));
}

func calculateWi_16_63 (i int, w []uint32) uint32 {
	return w[i-16] + s0 (w[i-15]) + w[i-7] + s1(w[i-2]);
}


// ==================================================================
// ==================================================================
// ==================================================================
// ==================================================================
// ==================================================================
var BCD_charArray []byte = []byte {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

func encodeBcd (in []byte) string {
	var _out []byte = make([]byte, len(in)*2);
	var _outIndex int;
	for _, _byte := range in {
		_nibble_high := (_byte & 0xF0) >> 4;
		_nibble_low  := _byte & 0x0F;
		_out[_outIndex] = BCD_charArray[_nibble_high];
		_outIndex++;
		_out[_outIndex] = BCD_charArray [_nibble_low];
		_outIndex++;
	}
	return string (_out);
}


