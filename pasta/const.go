package pasta

const FieldSizeInBits = 255

const (
	Poseidon3W     = byte(0x00)
	Poseidon5W     = byte(0x01)
	Poseidon3      = byte(0x02)
	MaxSpongeWidth = byte(0x05)
)

var GroupCoeffB = Field{0xa1a55e68ffffffed, 0x74c2a54b4f4982f3, 0xfffffffffffffffd, 0x3fffffffffffffff}
var FieldOne = Field{0x34786d38fffffffd, 0x992c350be41914ad, 0xffffffffffffffff, 0x3fffffffffffffff}
var FieldThree = Field{0x6b0ee5d0fffffff5, 0x86f76d2b99b14bd0, 0xfffffffffffffffe, 0x3fffffffffffffff}
var FieldFour = Field{0x65a221cfffffff1, 0xfddd093b747d6762, 0xfffffffffffffffd, 0x3fffffffffffffff}
var FieldEight = Field{0x7387134cffffffe1, 0xd973797adfadd5a8, 0xfffffffffffffffb, 0x3fffffffffffffff}
var FieldZero = Field{0, 0, 0, 0}
var ScalarZero = Scalar{0, 0, 0, 0}

var GroupZero = Group{
	X: Field{0, 0, 0, 0},
	Y: Field{0x34786d38fffffffd, 0x992c350be41914ad, 0xffffffffffffffff, 0x3fffffffffffffff},
	Z: Field{0, 0, 0, 0},
}

var AffineOne = Affine{
	X: Field{0x34786d38fffffffd, 0x992c350be41914ad, 0xffffffffffffffff, 0x3fffffffffffffff},
	Y: Field{0x2f474795455d409d, 0xb443b9b74b8255d9, 0x270c412f2c9a5d66, 0x8e00f71ba43dd6b},
}
