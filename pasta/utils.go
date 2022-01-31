package pasta

import "encoding/binary"

func BytesArrayToU64Array(bytes [32]byte) (out [4]uint64) {
	for i := 0; i < 4; i++ {
		out[i] = binary.LittleEndian.Uint64(bytes[i*8 : (i+1)*8])
	}
	return
}

func U64ArrayToBytesArray(in [4]uint64) (out [32]byte) {
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(out[i*8:(i+1)*8], in[i])
	}
	return
}

func BigEndianBytesToFqMontgomeryArray(in []byte) (out [4]uint64) {
	var inArray [32]byte
	copy(inArray[:], reverseBytes(in))
	FiatPastaFqToMontgomery(&out, BytesArrayToU64Array(inArray))
	return
}

func BigEndianBytesToFpMontgomeryArray(in []byte) (out [4]uint64) {
	var inArray [32]byte
	copy(inArray[:], reverseBytes(in))
	FiatPastaFpToMontgomery(&out, BytesArrayToU64Array(inArray))
	return
}

func FqMontgomeryArrayToBigEndianBytes(in [4]uint64) (out []byte) {
	var outArray [4]uint64
	FiatPastaFqFromMontgomery(&outArray, in)
	tmp := U64ArrayToBytesArray(outArray)
	out = reverseBytes(tmp[:])
	return
}

func FpMontgomeryArrayToBigEndianBytes(in [4]uint64) (out []byte) {
	var outArray [4]uint64
	FiatPastaFpFromMontgomery(&outArray, in)
	tmp := U64ArrayToBytesArray(outArray)
	out = reverseBytes(tmp[:])
	return
}

func BytesArrayTo32LengthBytesArray(in []byte) [32]byte {
	if len(in) != 32 {
		return [32]byte{}
	}
	var out [32]byte

	for i := 0; i < 32; i++ {
		out[i] = in[i]
	}
	return out
}

func reverseBytes(s []byte) []byte {
	out := make([]byte, 32)
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = s[j], s[i]
	}
	return out
}
