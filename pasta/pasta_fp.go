package pasta

type FiatPastaFpUint1 uint8
type FiatPastaFpInt1 int8

var PMinus1Over2 = []bool{true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true, false, false, false, true, false, false, true, false, false, false, true, true, false, true, false, false, true, true, false, false, false, true, true, true, true, true, true, false, false, false, false, false, false, true, false, false, true, false, true, false, false, true, true, false, false, true, true, true, true, true, false, false, true, false, false, false, true, true, false, true, true, true, false, false, true, true, false, false, true, false, false, true, false, true, true, false, true, false, false, true, true, false, false, false, false, true, true, true, false, true, true, false, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false}
var Pminus1Over2Len = 254

/*
 * The function fiat_pasta_fp_addcarryx_u64 is an addition with carry.
 * Postconditions:
 *   out1 = (arg1 + arg2 + arg3) mod 2^64
 *   out2 = ⌊(arg1 + arg2 + arg3) / 2^64⌋
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [0x0 ~> 0xffffffffffffffff]
 *   arg3: [0x0 ~> 0xffffffffffffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0xffffffffffffffff]
 *   out2: [0x0 ~> 0x1]
 */
func FiatPastaFpAddCarryXU64(out1 *uint64, out2 *FiatPastaFpUint1, arg1 FiatPastaFpUint1, arg2, arg3 uint64) {
	var tmp = arg3 + uint64(arg1)
	*out1 = arg2 + tmp

	if (arg2 > *out1) || (arg3 > tmp) == true {
		*out2 = 1
	} else {
		*out2 = 0
	}
}

/*
 * The function fiat_pasta_fp_subborrowx_u64 is a subtraction with borrow.
 * Postconditions:
 *   out1 = (-arg1 + arg2 + -arg3) mod 2^64
 *   out2 = -⌊(-arg1 + arg2 + -arg3) / 2^64⌋
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [0x0 ~> 0xffffffffffffffff]
 *   arg3: [0x0 ~> 0xffffffffffffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0xffffffffffffffff]
 *   out2: [0x0 ~> 0x1]
 */
func FiatPastaFpSubBorrowXU64(out1 *uint64, out2 *FiatPastaFpUint1, arg1 FiatPastaFpUint1, arg2, arg3 uint64) {
	var tmp = arg3 + uint64(arg1)
	*out1 = arg2 - tmp
	if (arg2 < *out1) || (arg3 > tmp) {
		*out2 = 1
	} else {
		*out2 = 0
	}
}

/*
 * The function fiat_pasta_fp_mulx_u64 is a multiplication, returning the full double-width result.
 * Postconditions:
 *   out1 = (arg1 * arg2) mod 2^64
 *   out2 = ⌊arg1 * arg2 / 2^64⌋
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0xffffffffffffffff]
 *   arg2: [0x0 ~> 0xffffffffffffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0xffffffffffffffff]
 *   out2: [0x0 ~> 0xffffffffffffffff]
 */
func FiatPastaFpMulXU64(out1, out2 *uint64, a, b uint64) {
	var a_lo = uint64(uint32(a))
	var a_hi = uint64(uint32(a >> 32))
	var b_lo = uint64(uint32(b))
	var b_hi = uint64(uint32(b >> 32))

	var a_x_b_hi = a_hi * b_hi
	var a_x_b_mid = a_hi * b_lo
	var b_x_a_mid = b_hi * a_lo
	var a_x_b_lo = a_lo * b_lo

	var carry_bit = (uint64(uint32(a_x_b_mid)) + uint64(uint32(b_x_a_mid)) + (a_x_b_lo >> 32)) >> 32
	var multhi = a_x_b_hi + (a_x_b_mid >> 32) + (b_x_a_mid >> 32) + carry_bit

	*out2 = multhi
	*out1 = a * b
}

/*
 * The function fiat_pasta_fp_cmovznz_u64 is a single-word conditional move.
 * Postconditions:
 *   out1 = (if arg1 = 0 then arg2 else arg3)
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [0x0 ~> 0xffffffffffffffff]
 *   arg3: [0x0 ~> 0xffffffffffffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0xffffffffffffffff]
 */
func FiatPastaFpCmovznzU64(out1 *uint64, arg1 FiatPastaFpUint1, arg2, arg3 uint64) {
	var x1 FiatPastaFpUint1
	var x2, x3 uint64
	x1 = arg1
	x2 = uint64(FiatPastaFpInt1(0x0-x1)) & uint64(0xffffffffffffffff)
	x3 = (x2 & arg3) | ((^x2) & arg2)
	*out1 = x3
}

/*
 * The function fiat_pasta_fp_mul multiplies two field elements in the Montgomery domain.
 * Preconditions:
 *   0 ≤ eval arg1 < m
 *   0 ≤ eval arg2 < m
 * Postconditions:
 *   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) * eval (from_montgomery arg2)) mod m
 *   0 ≤ eval out1 < m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 *   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
func FiatPastaFpMul(out1 *[4]uint64, arg1, arg2 [4]uint64) {
	var x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13 uint64
	var x14 FiatPastaFpUint1
	var x15 uint64
	var x16 FiatPastaFpUint1
	var x17 uint64
	var x18 FiatPastaFpUint1
	var x19, x20, x21, x22, x23, x24, x25, x26, x27, x28 uint64
	var x29 FiatPastaFpUint1
	var x30, x31 uint64
	var x32 FiatPastaFpUint1
	var x33 uint64
	var x34 FiatPastaFpUint1
	var x35 uint64
	var x36 FiatPastaFpUint1
	var x37 uint64
	var x38 FiatPastaFpUint1
	var x39 uint64
	var x40 FiatPastaFpUint1
	var x41, x42, x43, x44, x45, x46, x47, x48, x49 uint64
	var x50 FiatPastaFpUint1
	var x51 uint64
	var x52 FiatPastaFpUint1
	var x53 uint64
	var x54 FiatPastaFpUint1
	var x55, x56 uint64
	var x57 FiatPastaFpUint1
	var x58 uint64
	var x59 FiatPastaFpUint1
	var x60 uint64
	var x61 FiatPastaFpUint1
	var x62 uint64
	var x63 FiatPastaFpUint1
	var x64 uint64
	var x65 FiatPastaFpUint1
	var x66, x67, x68, x69, x70, x71, x72, x73, x74 uint64
	var x75 FiatPastaFpUint1
	var x76, x77 uint64
	var x78 FiatPastaFpUint1
	var x79 uint64
	var x80 FiatPastaFpUint1
	var x81 uint64
	var x82 FiatPastaFpUint1
	var x83 uint64
	var x84 FiatPastaFpUint1
	var x85 uint64
	var x86 FiatPastaFpUint1
	var x87, x88, x89, x90, x91, x92, x93, x94, x95, x96 uint64
	var x97 FiatPastaFpUint1
	var x98 uint64
	var x99 FiatPastaFpUint1
	var x100 uint64
	var x101 FiatPastaFpUint1
	var x102, x103 uint64
	var x104 FiatPastaFpUint1
	var x105 uint64
	var x106 FiatPastaFpUint1
	var x107 uint64
	var x108 FiatPastaFpUint1
	var x109 uint64
	var x110 FiatPastaFpUint1
	var x111 uint64
	var x112 FiatPastaFpUint1
	var x113, x114, x115, x116, x117, x118, x119, x120, x121 uint64
	var x122 FiatPastaFpUint1
	var x123, x124 uint64
	var x125 FiatPastaFpUint1
	var x126 uint64
	var x127 FiatPastaFpUint1
	var x128 uint64
	var x129 FiatPastaFpUint1
	var x130 uint64
	var x131 FiatPastaFpUint1
	var x132 uint64
	var x133 FiatPastaFpUint1
	var x134, x135, x136, x137, x138, x139, x140, x141, x142, x143 uint64
	var x144 FiatPastaFpUint1
	var x145 uint64
	var x146 FiatPastaFpUint1
	var x147 uint64
	var x148 FiatPastaFpUint1
	var x149, x150 uint64
	var x151 FiatPastaFpUint1
	var x152 uint64
	var x153 FiatPastaFpUint1
	var x154 uint64
	var x155 FiatPastaFpUint1
	var x156 uint64
	var x157 FiatPastaFpUint1
	var x158 uint64
	var x159 FiatPastaFpUint1
	var x160, x161, x162, x163, x164, x165, x166, x167, x168 uint64
	var x169 FiatPastaFpUint1
	var x170, x171 uint64
	var x172 FiatPastaFpUint1
	var x173 uint64
	var x174 FiatPastaFpUint1
	var x175 uint64
	var x176 FiatPastaFpUint1
	var x177 uint64
	var x178 FiatPastaFpUint1
	var x179 uint64
	var x180 FiatPastaFpUint1
	var x181, x182 uint64
	var x183 FiatPastaFpUint1
	var x184 uint64
	var x185 FiatPastaFpUint1
	var x186 uint64
	var x187 FiatPastaFpUint1
	var x188 uint64
	var x189 FiatPastaFpUint1
	var x190 uint64
	var x191 FiatPastaFpUint1
	var x192, x193, x194, x195 uint64

	x1 = arg1[1]
	x2 = arg1[2]
	x3 = arg1[3]
	x4 = arg1[0]

	FiatPastaFpMulXU64(&x5, &x6, x4, arg2[3])
	FiatPastaFpMulXU64(&x7, &x8, x4, arg2[2])
	FiatPastaFpMulXU64(&x9, &x10, x4, arg2[1])
	FiatPastaFpMulXU64(&x11, &x12, x4, arg2[0])
	FiatPastaFpAddCarryXU64(&x13, &x14, 0x0, x12, x9)
	FiatPastaFpAddCarryXU64(&x15, &x16, x14, x10, x7)
	FiatPastaFpAddCarryXU64(&x17, &x18, x16, x8, x5)

	x19 = uint64(x18) + x6

	FiatPastaFpMulXU64(&x20, &x21, x11, uint64(0x992d30ecffffffff))
	FiatPastaFpMulXU64(&x22, &x23, x20, uint64(0x4000000000000000))
	FiatPastaFpMulXU64(&x24, &x25, x20, uint64(0x224698fc094cf91b))
	FiatPastaFpMulXU64(&x26, &x27, x20, uint64(0x992d30ed00000001))
	FiatPastaFpAddCarryXU64(&x28, &x29, 0x0, x27, x24)

	x30 = uint64(x29) + x25

	FiatPastaFpAddCarryXU64(&x31, &x32, 0x0, x11, x26)
	FiatPastaFpAddCarryXU64(&x33, &x34, x32, x13, x28)
	FiatPastaFpAddCarryXU64(&x35, &x36, x34, x15, x30)
	FiatPastaFpAddCarryXU64(&x37, &x38, x36, x17, x22)
	FiatPastaFpAddCarryXU64(&x39, &x40, x38, x19, x23)
	FiatPastaFpMulXU64(&x41, &x42, x1, arg2[3])
	FiatPastaFpMulXU64(&x43, &x44, x1, arg2[2])
	FiatPastaFpMulXU64(&x45, &x46, x1, arg2[1])
	FiatPastaFpMulXU64(&x47, &x48, x1, arg2[0])
	FiatPastaFpAddCarryXU64(&x49, &x50, 0x0, x48, x45)
	FiatPastaFpAddCarryXU64(&x51, &x52, x50, x46, x43)
	FiatPastaFpAddCarryXU64(&x53, &x54, x52, x44, x41)

	x55 = uint64(x54) + x42

	FiatPastaFpAddCarryXU64(&x56, &x57, 0x0, x33, x47)
	FiatPastaFpAddCarryXU64(&x58, &x59, x57, x35, x49)
	FiatPastaFpAddCarryXU64(&x60, &x61, x59, x37, x51)
	FiatPastaFpAddCarryXU64(&x62, &x63, x61, x39, x53)
	FiatPastaFpAddCarryXU64(&x64, &x65, x63, uint64(x40), x55)
	FiatPastaFpMulXU64(&x66, &x67, x56, uint64(0x992d30ecffffffff))
	FiatPastaFpMulXU64(&x68, &x69, x66, uint64(0x4000000000000000))
	FiatPastaFpMulXU64(&x70, &x71, x66, uint64(0x224698fc094cf91b))
	FiatPastaFpMulXU64(&x72, &x73, x66, uint64(0x992d30ed00000001))
	FiatPastaFpAddCarryXU64(&x74, &x75, 0x0, x73, x70)

	x76 = uint64(x75) + x71

	FiatPastaFpAddCarryXU64(&x77, &x78, 0x0, x56, x72)
	FiatPastaFpAddCarryXU64(&x79, &x80, x78, x58, x74)
	FiatPastaFpAddCarryXU64(&x81, &x82, x80, x60, x76)
	FiatPastaFpAddCarryXU64(&x83, &x84, x82, x62, x68)
	FiatPastaFpAddCarryXU64(&x85, &x86, x84, x64, x69)

	x87 = uint64(x86) + uint64(x65)

	FiatPastaFpMulXU64(&x88, &x89, x2, arg2[3])
	FiatPastaFpMulXU64(&x90, &x91, x2, arg2[2])
	FiatPastaFpMulXU64(&x92, &x93, x2, arg2[1])
	FiatPastaFpMulXU64(&x94, &x95, x2, arg2[0])
	FiatPastaFpAddCarryXU64(&x96, &x97, 0x0, x95, x92)
	FiatPastaFpAddCarryXU64(&x98, &x99, x97, x93, x90)
	FiatPastaFpAddCarryXU64(&x100, &x101, x99, x91, x88)

	x102 = uint64(x101) + x89

	FiatPastaFpAddCarryXU64(&x103, &x104, 0x0, x79, x94)
	FiatPastaFpAddCarryXU64(&x105, &x106, x104, x81, x96)
	FiatPastaFpAddCarryXU64(&x107, &x108, x106, x83, x98)
	FiatPastaFpAddCarryXU64(&x109, &x110, x108, x85, x100)
	FiatPastaFpAddCarryXU64(&x111, &x112, x110, x87, x102)
	FiatPastaFpMulXU64(&x113, &x114, x103, uint64(0x992d30ecffffffff))
	FiatPastaFpMulXU64(&x115, &x116, x113, uint64(0x4000000000000000))
	FiatPastaFpMulXU64(&x117, &x118, x113, uint64(0x224698fc094cf91b))
	FiatPastaFpMulXU64(&x119, &x120, x113, uint64(0x992d30ed00000001))
	FiatPastaFpAddCarryXU64(&x121, &x122, 0x0, x120, x117)

	x123 = uint64(x122) + x118

	FiatPastaFpAddCarryXU64(&x124, &x125, 0x0, x103, x119)
	FiatPastaFpAddCarryXU64(&x126, &x127, x125, x105, x121)
	FiatPastaFpAddCarryXU64(&x128, &x129, x127, x107, x123)
	FiatPastaFpAddCarryXU64(&x130, &x131, x129, x109, x115)
	FiatPastaFpAddCarryXU64(&x132, &x133, x131, x111, x116)

	x134 = uint64(x133) + uint64(x112)

	FiatPastaFpMulXU64(&x135, &x136, x3, arg2[3])
	FiatPastaFpMulXU64(&x137, &x138, x3, arg2[2])
	FiatPastaFpMulXU64(&x139, &x140, x3, arg2[1])
	FiatPastaFpMulXU64(&x141, &x142, x3, arg2[0])
	FiatPastaFpAddCarryXU64(&x143, &x144, 0x0, x142, x139)
	FiatPastaFpAddCarryXU64(&x145, &x146, x144, x140, x137)
	FiatPastaFpAddCarryXU64(&x147, &x148, x146, x138, x135)

	x149 = uint64(x148) + x136

	FiatPastaFpAddCarryXU64(&x150, &x151, 0x0, x126, x141)
	FiatPastaFpAddCarryXU64(&x152, &x153, x151, x128, x143)
	FiatPastaFpAddCarryXU64(&x154, &x155, x153, x130, x145)
	FiatPastaFpAddCarryXU64(&x156, &x157, x155, x132, x147)
	FiatPastaFpAddCarryXU64(&x158, &x159, x157, x134, x149)
	FiatPastaFpMulXU64(&x160, &x161, x150, uint64(0x992d30ecffffffff))
	FiatPastaFpMulXU64(&x162, &x163, x160, uint64(0x4000000000000000))
	FiatPastaFpMulXU64(&x164, &x165, x160, uint64(0x224698fc094cf91b))
	FiatPastaFpMulXU64(&x166, &x167, x160, uint64(0x992d30ed00000001))
	FiatPastaFpAddCarryXU64(&x168, &x169, 0x0, x167, x164)

	x170 = uint64(x169) + x165

	FiatPastaFpAddCarryXU64(&x171, &x172, 0x0, x150, x166)
	FiatPastaFpAddCarryXU64(&x173, &x174, x172, x152, x168)
	FiatPastaFpAddCarryXU64(&x175, &x176, x174, x154, x170)
	FiatPastaFpAddCarryXU64(&x177, &x178, x176, x156, x162)
	FiatPastaFpAddCarryXU64(&x179, &x180, x178, x158, x163)

	x181 = uint64(x180) + uint64(x159)

	FiatPastaFpSubBorrowXU64(&x182, &x183, 0x0, x173, uint64(0x992d30ed00000001))
	FiatPastaFpSubBorrowXU64(&x184, &x185, x183, x175, uint64(0x224698fc094cf91b))
	FiatPastaFpSubBorrowXU64(&x186, &x187, x185, x177, uint64(0x0))
	FiatPastaFpSubBorrowXU64(&x188, &x189, x187, x179, uint64(0x4000000000000000))
	FiatPastaFpSubBorrowXU64(&x190, &x191, x189, x181, uint64(0x0))
	FiatPastaFpCmovznzU64(&x192, x191, x182, x173)
	FiatPastaFpCmovznzU64(&x193, x191, x184, x175)
	FiatPastaFpCmovznzU64(&x194, x191, x186, x177)
	FiatPastaFpCmovznzU64(&x195, x191, x188, x179)

	out1[0] = x192
	out1[1] = x193
	out1[2] = x194
	out1[3] = x195
}

/*
 * The function fiat_pasta_fp_square squares a field element in the Montgomery domain.
 * Preconditions:
 *   0 ≤ eval arg1 < m
 * Postconditions:
 *   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) * eval (from_montgomery arg1)) mod m
 *   0 ≤ eval out1 < m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
func FiatPastaFpSquare(out1 *[4]uint64, arg1 [4]uint64) {
	var x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13 uint64
	var x14 FiatPastaFpUint1
	var x15 uint64
	var x16 FiatPastaFpUint1
	var x17 uint64
	var x18 FiatPastaFpUint1
	var x19, x20, x21, x22, x23, x24, x25, x26, x27, x28 uint64
	var x29 FiatPastaFpUint1
	var x30, x31 uint64
	var x32 FiatPastaFpUint1
	var x33 uint64
	var x34 FiatPastaFpUint1
	var x35 uint64
	var x36 FiatPastaFpUint1
	var x37 uint64
	var x38 FiatPastaFpUint1
	var x39 uint64
	var x40 FiatPastaFpUint1
	var x41, x42, x43, x44, x45, x46, x47, x48, x49 uint64
	var x50 FiatPastaFpUint1
	var x51 uint64
	var x52 FiatPastaFpUint1
	var x53 uint64
	var x54 FiatPastaFpUint1
	var x55, x56 uint64
	var x57 FiatPastaFpUint1
	var x58 uint64
	var x59 FiatPastaFpUint1
	var x60 uint64
	var x61 FiatPastaFpUint1
	var x62 uint64
	var x63 FiatPastaFpUint1
	var x64 uint64
	var x65 FiatPastaFpUint1
	var x66, x67, x68, x69, x70, x71, x72, x73, x74 uint64
	var x75 FiatPastaFpUint1
	var x76, x77 uint64
	var x78 FiatPastaFpUint1
	var x79 uint64
	var x80 FiatPastaFpUint1
	var x81 uint64
	var x82 FiatPastaFpUint1
	var x83 uint64
	var x84 FiatPastaFpUint1
	var x85 uint64
	var x86 FiatPastaFpUint1
	var x87, x88, x89, x90, x91, x92, x93, x94, x95, x96 uint64
	var x97 FiatPastaFpUint1
	var x98 uint64
	var x99 FiatPastaFpUint1
	var x100 uint64
	var x101 FiatPastaFpUint1
	var x102, x103 uint64
	var x104 FiatPastaFpUint1
	var x105 uint64
	var x106 FiatPastaFpUint1
	var x107 uint64
	var x108 FiatPastaFpUint1
	var x109 uint64
	var x110 FiatPastaFpUint1
	var x111 uint64
	var x112 FiatPastaFpUint1
	var x113, x114, x115, x116, x117, x118, x119, x120, x121 uint64
	var x122 FiatPastaFpUint1
	var x123, x124 uint64
	var x125 FiatPastaFpUint1
	var x126 uint64
	var x127 FiatPastaFpUint1
	var x128 uint64
	var x129 FiatPastaFpUint1
	var x130 uint64
	var x131 FiatPastaFpUint1
	var x132 uint64
	var x133 FiatPastaFpUint1
	var x134, x135, x136, x137, x138, x139, x140, x141, x142, x143 uint64
	var x144 FiatPastaFpUint1
	var x145 uint64
	var x146 FiatPastaFpUint1
	var x147 uint64
	var x148 FiatPastaFpUint1
	var x149, x150 uint64
	var x151 FiatPastaFpUint1
	var x152 uint64
	var x153 FiatPastaFpUint1
	var x154 uint64
	var x155 FiatPastaFpUint1
	var x156 uint64
	var x157 FiatPastaFpUint1
	var x158 uint64
	var x159 FiatPastaFpUint1
	var x160, x161, x162, x163, x164, x165, x166, x167, x168 uint64
	var x169 FiatPastaFpUint1
	var x170, x171 uint64
	var x172 FiatPastaFpUint1
	var x173 uint64
	var x174 FiatPastaFpUint1
	var x175 uint64
	var x176 FiatPastaFpUint1
	var x177 uint64
	var x178 FiatPastaFpUint1
	var x179 uint64
	var x180 FiatPastaFpUint1
	var x181, x182 uint64
	var x183 FiatPastaFpUint1
	var x184 uint64
	var x185 FiatPastaFpUint1
	var x186 uint64
	var x187 FiatPastaFpUint1
	var x188 uint64
	var x189 FiatPastaFpUint1
	var x190 uint64
	var x191 FiatPastaFpUint1
	var x192, x193, x194, x195 uint64

	x1 = arg1[1]
	x2 = arg1[2]
	x3 = arg1[3]
	x4 = arg1[0]

	FiatPastaFpMulXU64(&x5, &x6, x4, arg1[3])
	FiatPastaFpMulXU64(&x7, &x8, x4, arg1[2])
	FiatPastaFpMulXU64(&x9, &x10, x4, arg1[1])
	FiatPastaFpMulXU64(&x11, &x12, x4, arg1[0])
	FiatPastaFpAddCarryXU64(&x13, &x14, 0x0, x12, x9)
	FiatPastaFpAddCarryXU64(&x15, &x16, x14, x10, x7)
	FiatPastaFpAddCarryXU64(&x17, &x18, x16, x8, x5)

	x19 = uint64(x18) + x6

	FiatPastaFpMulXU64(&x20, &x21, x11, uint64(0x992d30ecffffffff))
	FiatPastaFpMulXU64(&x22, &x23, x20, uint64(0x4000000000000000))
	FiatPastaFpMulXU64(&x24, &x25, x20, uint64(0x224698fc094cf91b))
	FiatPastaFpMulXU64(&x26, &x27, x20, uint64(0x992d30ed00000001))
	FiatPastaFpAddCarryXU64(&x28, &x29, 0x0, x27, x24)

	x30 = uint64(x29) + x25

	FiatPastaFpAddCarryXU64(&x31, &x32, 0x0, x11, x26)
	FiatPastaFpAddCarryXU64(&x33, &x34, x32, x13, x28)
	FiatPastaFpAddCarryXU64(&x35, &x36, x34, x15, x30)
	FiatPastaFpAddCarryXU64(&x37, &x38, x36, x17, x22)
	FiatPastaFpAddCarryXU64(&x39, &x40, x38, x19, x23)
	FiatPastaFpMulXU64(&x41, &x42, x1, arg1[3])
	FiatPastaFpMulXU64(&x43, &x44, x1, arg1[2])
	FiatPastaFpMulXU64(&x45, &x46, x1, arg1[1])
	FiatPastaFpMulXU64(&x47, &x48, x1, arg1[0])
	FiatPastaFpAddCarryXU64(&x49, &x50, 0x0, x48, x45)
	FiatPastaFpAddCarryXU64(&x51, &x52, x50, x46, x43)
	FiatPastaFpAddCarryXU64(&x53, &x54, x52, x44, x41)

	x55 = uint64(x54) + x42

	FiatPastaFpAddCarryXU64(&x56, &x57, 0x0, x33, x47)
	FiatPastaFpAddCarryXU64(&x58, &x59, x57, x35, x49)
	FiatPastaFpAddCarryXU64(&x60, &x61, x59, x37, x51)
	FiatPastaFpAddCarryXU64(&x62, &x63, x61, x39, x53)
	FiatPastaFpAddCarryXU64(&x64, &x65, x63, uint64(x40), x55)
	FiatPastaFpMulXU64(&x66, &x67, x56, uint64(0x992d30ecffffffff))
	FiatPastaFpMulXU64(&x68, &x69, x66, uint64(0x4000000000000000))
	FiatPastaFpMulXU64(&x70, &x71, x66, uint64(0x224698fc094cf91b))
	FiatPastaFpMulXU64(&x72, &x73, x66, uint64(0x992d30ed00000001))
	FiatPastaFpAddCarryXU64(&x74, &x75, 0x0, x73, x70)

	x76 = uint64(x75) + x71

	FiatPastaFpAddCarryXU64(&x77, &x78, 0x0, x56, x72)
	FiatPastaFpAddCarryXU64(&x79, &x80, x78, x58, x74)
	FiatPastaFpAddCarryXU64(&x81, &x82, x80, x60, x76)
	FiatPastaFpAddCarryXU64(&x83, &x84, x82, x62, x68)
	FiatPastaFpAddCarryXU64(&x85, &x86, x84, x64, x69)

	x87 = uint64(x86) + uint64(x65)

	FiatPastaFpMulXU64(&x88, &x89, x2, arg1[3])
	FiatPastaFpMulXU64(&x90, &x91, x2, arg1[2])
	FiatPastaFpMulXU64(&x92, &x93, x2, arg1[1])
	FiatPastaFpMulXU64(&x94, &x95, x2, arg1[0])
	FiatPastaFpAddCarryXU64(&x96, &x97, 0x0, x95, x92)
	FiatPastaFpAddCarryXU64(&x98, &x99, x97, x93, x90)
	FiatPastaFpAddCarryXU64(&x100, &x101, x99, x91, x88)

	x102 = uint64(x101) + x89

	FiatPastaFpAddCarryXU64(&x103, &x104, 0x0, x79, x94)
	FiatPastaFpAddCarryXU64(&x105, &x106, x104, x81, x96)
	FiatPastaFpAddCarryXU64(&x107, &x108, x106, x83, x98)
	FiatPastaFpAddCarryXU64(&x109, &x110, x108, x85, x100)
	FiatPastaFpAddCarryXU64(&x111, &x112, x110, x87, x102)
	FiatPastaFpMulXU64(&x113, &x114, x103, uint64(0x992d30ecffffffff))
	FiatPastaFpMulXU64(&x115, &x116, x113, uint64(0x4000000000000000))
	FiatPastaFpMulXU64(&x117, &x118, x113, uint64(0x224698fc094cf91b))
	FiatPastaFpMulXU64(&x119, &x120, x113, uint64(0x992d30ed00000001))
	FiatPastaFpAddCarryXU64(&x121, &x122, 0x0, x120, x117)

	x123 = uint64(x122) + x118

	FiatPastaFpAddCarryXU64(&x124, &x125, 0x0, x103, x119)
	FiatPastaFpAddCarryXU64(&x126, &x127, x125, x105, x121)
	FiatPastaFpAddCarryXU64(&x128, &x129, x127, x107, x123)
	FiatPastaFpAddCarryXU64(&x130, &x131, x129, x109, x115)
	FiatPastaFpAddCarryXU64(&x132, &x133, x131, x111, x116)

	x134 = uint64(x133) + uint64(x112)

	FiatPastaFpMulXU64(&x135, &x136, x3, arg1[3])
	FiatPastaFpMulXU64(&x137, &x138, x3, arg1[2])
	FiatPastaFpMulXU64(&x139, &x140, x3, arg1[1])
	FiatPastaFpMulXU64(&x141, &x142, x3, arg1[0])
	FiatPastaFpAddCarryXU64(&x143, &x144, 0x0, x142, x139)
	FiatPastaFpAddCarryXU64(&x145, &x146, x144, x140, x137)
	FiatPastaFpAddCarryXU64(&x147, &x148, x146, x138, x135)

	x149 = uint64(x148) + x136

	FiatPastaFpAddCarryXU64(&x150, &x151, 0x0, x126, x141)
	FiatPastaFpAddCarryXU64(&x152, &x153, x151, x128, x143)
	FiatPastaFpAddCarryXU64(&x154, &x155, x153, x130, x145)
	FiatPastaFpAddCarryXU64(&x156, &x157, x155, x132, x147)
	FiatPastaFpAddCarryXU64(&x158, &x159, x157, x134, x149)
	FiatPastaFpMulXU64(&x160, &x161, x150, uint64(0x992d30ecffffffff))
	FiatPastaFpMulXU64(&x162, &x163, x160, uint64(0x4000000000000000))
	FiatPastaFpMulXU64(&x164, &x165, x160, uint64(0x224698fc094cf91b))
	FiatPastaFpMulXU64(&x166, &x167, x160, uint64(0x992d30ed00000001))
	FiatPastaFpAddCarryXU64(&x168, &x169, 0x0, x167, x164)

	x170 = uint64(x169) + x165

	FiatPastaFpAddCarryXU64(&x171, &x172, 0x0, x150, x166)
	FiatPastaFpAddCarryXU64(&x173, &x174, x172, x152, x168)
	FiatPastaFpAddCarryXU64(&x175, &x176, x174, x154, x170)
	FiatPastaFpAddCarryXU64(&x177, &x178, x176, x156, x162)
	FiatPastaFpAddCarryXU64(&x179, &x180, x178, x158, x163)

	x181 = uint64(x180) + uint64(x159)

	FiatPastaFpSubBorrowXU64(&x182, &x183, 0x0, x173, uint64(0x992d30ed00000001))
	FiatPastaFpSubBorrowXU64(&x184, &x185, x183, x175, uint64(0x224698fc094cf91b))
	FiatPastaFpSubBorrowXU64(&x186, &x187, x185, x177, uint64(0x0))
	FiatPastaFpSubBorrowXU64(&x188, &x189, x187, x179, uint64(0x4000000000000000))
	FiatPastaFpSubBorrowXU64(&x190, &x191, x189, x181, uint64(0x0))
	FiatPastaFpCmovznzU64(&x192, x191, x182, x173)
	FiatPastaFpCmovznzU64(&x193, x191, x184, x175)
	FiatPastaFpCmovznzU64(&x194, x191, x186, x177)
	FiatPastaFpCmovznzU64(&x195, x191, x188, x179)

	out1[0] = x192
	out1[1] = x193
	out1[2] = x194
	out1[3] = x195
}

/*
 * The function fiat_pasta_fq_add adds two field elements in the Montgomery domain.
 * Preconditions:
 *   0 ≤ eval arg1 < m
 *   0 ≤ eval arg2 < m
 * Postconditions:
 *   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) + eval (from_montgomery arg2)) mod m
 *   0 ≤ eval out1 < m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 *   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
func FiatPastaFpAdd(out1 *[4]uint64, arg1, arg2 [4]uint64) {
	var x1 uint64
	var x2 FiatPastaFpUint1
	var x3 uint64
	var x4 FiatPastaFpUint1
	var x5 uint64
	var x6 FiatPastaFpUint1
	var x7 uint64
	var x8 FiatPastaFpUint1
	var x9 uint64
	var x10 FiatPastaFpUint1
	var x11 uint64
	var x12 FiatPastaFpUint1
	var x13 uint64
	var x14 FiatPastaFpUint1
	var x15 uint64
	var x16 FiatPastaFpUint1
	var x17 uint64
	var x18 FiatPastaFpUint1
	var x19 uint64
	var x20 uint64
	var x21 uint64
	var x22 uint64

	FiatPastaFpAddCarryXU64(&x1, &x2, 0x0, arg1[0], arg2[0])
	FiatPastaFpAddCarryXU64(&x3, &x4, x2, arg1[1], arg2[1])
	FiatPastaFpAddCarryXU64(&x5, &x6, x4, arg1[2], arg2[2])
	FiatPastaFpAddCarryXU64(&x7, &x8, x6, arg1[3], arg2[3])
	FiatPastaFpSubBorrowXU64(&x9, &x10, 0x0, x1, uint64(0x992d30ed00000001))
	FiatPastaFpSubBorrowXU64(&x11, &x12, x10, x3, uint64(0x224698fc094cf91b))
	FiatPastaFpSubBorrowXU64(&x13, &x14, x12, x5, 0x0)
	FiatPastaFpSubBorrowXU64(&x15, &x16, x14, x7, uint64(0x4000000000000000))
	FiatPastaFpSubBorrowXU64(&x17, &x18, x16, uint64(x8), 0x0)
	FiatPastaFpCmovznzU64(&x19, x18, x9, x1)
	FiatPastaFpCmovznzU64(&x20, x18, x11, x3)
	FiatPastaFpCmovznzU64(&x21, x18, x13, x5)
	FiatPastaFpCmovznzU64(&x22, x18, x15, x7)
	out1[0] = x19
	out1[1] = x20
	out1[2] = x21
	out1[3] = x22
}

/*
 * The function fiat_pasta_fp_sub subtracts two field elements in the Montgomery domain.
 * Preconditions:
 *   0 ≤ eval arg1 < m
 *   0 ≤ eval arg2 < m
 * Postconditions:
 *   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) - eval (from_montgomery arg2)) mod m
 *   0 ≤ eval out1 < m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 *   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
func FiatPastaFpSub(out1 *[4]uint64, arg1, arg2 [4]uint64) {
	var x1 uint64
	var x2 FiatPastaFpUint1
	var x3 uint64
	var x4 FiatPastaFpUint1
	var x5 uint64
	var x6 FiatPastaFpUint1
	var x7 uint64
	var x8 FiatPastaFpUint1
	var x9, x10 uint64
	var x11 FiatPastaFpUint1
	var x12 uint64
	var x13 FiatPastaFpUint1
	var x14 uint64
	var x15 FiatPastaFpUint1
	var x16 uint64
	var x17 FiatPastaFpUint1

	FiatPastaFpSubBorrowXU64(&x1, &x2, 0x0, arg1[0], arg2[0])
	FiatPastaFpSubBorrowXU64(&x3, &x4, x2, arg1[1], arg2[1])
	FiatPastaFpSubBorrowXU64(&x5, &x6, x4, arg1[2], arg2[2])
	FiatPastaFpSubBorrowXU64(&x7, &x8, x6, arg1[3], arg2[3])
	FiatPastaFpCmovznzU64(&x9, x8, 0x0, uint64(0xffffffffffffffff))
	FiatPastaFpAddCarryXU64(&x10, &x11, 0x0, x1, x9&uint64(0x992d30ed00000001))
	FiatPastaFpAddCarryXU64(&x12, &x13, x11, x3, x9&uint64(0x224698fc094cf91b))
	FiatPastaFpAddCarryXU64(&x14, &x15, x13, x5, uint64(0x0))
	FiatPastaFpAddCarryXU64(&x16, &x17, x15, x7, x9&uint64(0x4000000000000000))

	out1[0] = x10
	out1[1] = x12
	out1[2] = x14
	out1[3] = x16
}

/*
 * The function fiat_pasta_fp_opp negates a field element in the Montgomery domain.
 * Preconditions:
 *   0 ≤ eval arg1 < m
 * Postconditions:
 *   eval (from_montgomery out1) mod m = -eval (from_montgomery arg1) mod m
 *   0 ≤ eval out1 < m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
func FiatPastaFpOpp(out1 *[4]uint64, arg1 [4]uint64) {
	var x1 uint64
	var x2 FiatPastaFpUint1
	var x3 uint64
	var x4 FiatPastaFpUint1
	var x5 uint64
	var x6 FiatPastaFpUint1
	var x7 uint64
	var x8 FiatPastaFpUint1
	var x9, x10 uint64
	var x11 FiatPastaFpUint1
	var x12 uint64
	var x13 FiatPastaFpUint1
	var x14 uint64
	var x15 FiatPastaFpUint1
	var x16 uint64
	var x17 FiatPastaFpUint1

	FiatPastaFpSubBorrowXU64(&x1, &x2, 0x0, 0x0, arg1[0])
	FiatPastaFpSubBorrowXU64(&x3, &x4, x2, 0x0, arg1[1])
	FiatPastaFpSubBorrowXU64(&x5, &x6, x4, 0x0, arg1[2])
	FiatPastaFpSubBorrowXU64(&x7, &x8, x6, 0x0, arg1[3])
	FiatPastaFpCmovznzU64(&x9, x8, 0x0, uint64(0xffffffffffffffff))
	FiatPastaFpAddCarryXU64(&x10, &x11, 0x0, x1, x9&uint64(0x992d30ed00000001))
	FiatPastaFpAddCarryXU64(&x12, &x13, x11, x3, x9&uint64(0x224698fc094cf91b))
	FiatPastaFpAddCarryXU64(&x14, &x15, x13, x5, uint64(0x0))
	FiatPastaFpAddCarryXU64(&x16, &x17, x15, x7, x9&uint64(0x4000000000000000))

	out1[0] = x10
	out1[1] = x12
	out1[2] = x14
	out1[3] = x16
}

/*
 * The function fiat_pasta_fp_from_montgomery translates a field element out of the Montgomery domain.
 * Preconditions:
 *   0 ≤ eval arg1 < m
 * Postconditions:
 *   eval out1 mod m = (eval arg1 * ((2^64)⁻¹ mod m)^4) mod m
 *   0 ≤ eval out1 < m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
func FiatPastaFpFromMontgomery(out1 *[4]uint64, arg1 [4]uint64) {
	var x1, x2, x3, x4, x5, x6, x7, x8, x9, x10 uint64
	var x11 FiatPastaFpUint1
	var x12 uint64
	var x13 FiatPastaFpUint1
	var x14 uint64
	var x15 FiatPastaFpUint1
	var x16 uint64
	var x17 FiatPastaFpUint1
	var x18, x19, x20, x21, x22, x23, x24, x25, x26 uint64
	var x27 FiatPastaFpUint1
	var x28 uint64
	var x29 FiatPastaFpUint1
	var x30 uint64
	var x31 FiatPastaFpUint1
	var x32 uint64
	var x33 FiatPastaFpUint1
	var x34 uint64
	var x35 FiatPastaFpUint1
	var x36 uint64
	var x37 FiatPastaFpUint1
	var x38 uint64
	var x39 FiatPastaFpUint1
	var x40 uint64
	var x41 FiatPastaFpUint1
	var x42, x43, x44, x45, x46, x47, x48, x49, x50 uint64
	var x51 FiatPastaFpUint1
	var x52 uint64
	var x53 FiatPastaFpUint1
	var x54 uint64
	var x55 FiatPastaFpUint1
	var x56 uint64
	var x57 FiatPastaFpUint1
	var x58 uint64
	var x59 FiatPastaFpUint1
	var x60 uint64
	var x61 FiatPastaFpUint1
	var x62 uint64
	var x63 FiatPastaFpUint1
	var x64 uint64
	var x65 FiatPastaFpUint1
	var x66, x67, x68, x69, x70, x71, x72, x73, x74 uint64
	var x75 FiatPastaFpUint1
	var x76 uint64
	var x77 FiatPastaFpUint1
	var x78 uint64
	var x79 FiatPastaFpUint1
	var x80 uint64
	var x81 FiatPastaFpUint1
	var x82 uint64
	var x83 FiatPastaFpUint1
	var x84, x85 uint64
	var x86 FiatPastaFpUint1
	var x87 uint64
	var x88 FiatPastaFpUint1
	var x89 uint64
	var x90 FiatPastaFpUint1
	var x91 uint64
	var x92 FiatPastaFpUint1
	var x93 uint64
	var x94 FiatPastaFpUint1
	var x95, x96, x97, x98 uint64

	x1 = arg1[0]

	FiatPastaFpMulXU64(&x2, &x3, x1, uint64(0x992d30ecffffffff))
	FiatPastaFpMulXU64(&x4, &x5, x2, uint64(0x4000000000000000))
	FiatPastaFpMulXU64(&x6, &x7, x2, uint64(0x224698fc094cf91b))
	FiatPastaFpMulXU64(&x8, &x9, x2, uint64(0x992d30ed00000001))
	FiatPastaFpAddCarryXU64(&x10, &x11, 0x0, x9, x6)
	FiatPastaFpAddCarryXU64(&x12, &x13, 0x0, x1, x8)
	FiatPastaFpAddCarryXU64(&x14, &x15, x13, 0x0, x10)
	FiatPastaFpAddCarryXU64(&x16, &x17, 0x0, x14, arg1[1])
	FiatPastaFpMulXU64(&x18, &x19, x16, uint64(0x992d30ecffffffff))
	FiatPastaFpMulXU64(&x20, &x21, x18, uint64(0x4000000000000000))
	FiatPastaFpMulXU64(&x22, &x23, x18, uint64(0x224698fc094cf91b))
	FiatPastaFpMulXU64(&x24, &x25, x18, uint64(0x992d30ed00000001))
	FiatPastaFpAddCarryXU64(&x26, &x27, 0x0, x25, x22)
	FiatPastaFpAddCarryXU64(&x28, &x29, 0x0, x16, x24)
	FiatPastaFpAddCarryXU64(&x30, &x31, x29, uint64(x17)+(uint64(x15)+(uint64(x11)+x7)), x26)
	FiatPastaFpAddCarryXU64(&x32, &x33, x31, x4, uint64(x27)+x23)
	FiatPastaFpAddCarryXU64(&x34, &x35, x33, x5, x20)
	FiatPastaFpAddCarryXU64(&x36, &x37, 0x0, x30, arg1[2])
	FiatPastaFpAddCarryXU64(&x38, &x39, x37, x32, 0x0)
	FiatPastaFpAddCarryXU64(&x40, &x41, x39, x34, 0x0)
	FiatPastaFpMulXU64(&x42, &x43, x36, uint64(0x992d30ecffffffff))
	FiatPastaFpMulXU64(&x44, &x45, x42, uint64(0x4000000000000000))
	FiatPastaFpMulXU64(&x46, &x47, x42, uint64(0x224698fc094cf91b))
	FiatPastaFpMulXU64(&x48, &x49, x42, uint64(0x992d30ed00000001))
	FiatPastaFpAddCarryXU64(&x50, &x51, 0x0, x49, x46)
	FiatPastaFpAddCarryXU64(&x52, &x53, 0x0, x36, x48)
	FiatPastaFpAddCarryXU64(&x54, &x55, x53, x38, x50)
	FiatPastaFpAddCarryXU64(&x56, &x57, x55, x40, uint64(x51)+x47)
	FiatPastaFpAddCarryXU64(&x58, &x59, x57, uint64(x41)+(uint64(x35)+x21), x44)
	FiatPastaFpAddCarryXU64(&x60, &x61, 0x0, x54, arg1[3])
	FiatPastaFpAddCarryXU64(&x62, &x63, x61, x56, 0x0)
	FiatPastaFpAddCarryXU64(&x64, &x65, x63, x58, 0x0)
	FiatPastaFpMulXU64(&x66, &x67, x60, uint64(0x992d30ecffffffff))
	FiatPastaFpMulXU64(&x68, &x69, x66, uint64(0x4000000000000000))
	FiatPastaFpMulXU64(&x70, &x71, x66, uint64(0x224698fc094cf91b))
	FiatPastaFpMulXU64(&x72, &x73, x66, uint64(0x992d30ed00000001))
	FiatPastaFpAddCarryXU64(&x74, &x75, 0x0, x73, x70)
	FiatPastaFpAddCarryXU64(&x76, &x77, 0x0, x60, x72)
	FiatPastaFpAddCarryXU64(&x78, &x79, x77, x62, x74)
	FiatPastaFpAddCarryXU64(&x80, &x81, x79, x64, uint64(x75)+x71)
	FiatPastaFpAddCarryXU64(&x82, &x83, x81, uint64(x65)+(uint64(x59)+x45), x68)
	x84 = uint64(x83) + x69
	FiatPastaFpSubBorrowXU64(&x85, &x86, 0x0, x78, uint64(0x992d30ed00000001))
	FiatPastaFpSubBorrowXU64(&x87, &x88, x86, x80, uint64(0x224698fc094cf91b))
	FiatPastaFpSubBorrowXU64(&x89, &x90, x88, x82, 0x0)
	FiatPastaFpSubBorrowXU64(&x91, &x92, x90, x84, uint64(0x4000000000000000))
	FiatPastaFpSubBorrowXU64(&x93, &x94, x92, 0x0, 0x0)
	FiatPastaFpCmovznzU64(&x95, x94, x85, x78)
	FiatPastaFpCmovznzU64(&x96, x94, x87, x80)
	FiatPastaFpCmovznzU64(&x97, x94, x89, x82)
	FiatPastaFpCmovznzU64(&x98, x94, x91, x84)
	out1[0] = x95
	out1[1] = x96
	out1[2] = x97
	out1[3] = x98

}

/*
 * The function fiat_pasta_fp_to_montgomery translates a field element into the Montgomery domain.
 * Preconditions:
 *   0 ≤ eval arg1 < m
 * Postconditions:
 *   eval (from_montgomery out1) mod m = eval arg1 mod m
 *   0 ≤ eval out1 < m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
func FiatPastaFpToMontgomery(out1 *[4]uint64, arg1 [4]uint64) {
	var x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13 uint64
	var x14 FiatPastaFpUint1
	var x15 uint64
	var x16 FiatPastaFpUint1
	var x17 uint64
	var x18 FiatPastaFpUint1
	var x19, x20, x21, x22, x23, x24, x25, x26, x27 uint64
	var x28 FiatPastaFpUint1
	var x29 uint64
	var x30 FiatPastaFpUint1
	var x31 uint64
	var x32 FiatPastaFpUint1
	var x33 uint64
	var x34 FiatPastaFpUint1
	var x35 uint64
	var x36 FiatPastaFpUint1
	var x37, x38, x39, x40, x41, x42, x43, x44, x45 uint64
	var x46 FiatPastaFpUint1
	var x47 uint64
	var x48 FiatPastaFpUint1
	var x49 uint64
	var x50 FiatPastaFpUint1
	var x51 uint64
	var x52 FiatPastaFpUint1
	var x53 uint64
	var x54 FiatPastaFpUint1
	var x55 uint64
	var x56 FiatPastaFpUint1
	var x57 uint64
	var x58 FiatPastaFpUint1
	var x59, x60, x61, x62, x63, x64, x65, x66, x67 uint64
	var x68 FiatPastaFpUint1
	var x69 uint64
	var x70 FiatPastaFpUint1
	var x71 uint64
	var x72 FiatPastaFpUint1
	var x73 uint64
	var x74 FiatPastaFpUint1
	var x75 uint64
	var x76 FiatPastaFpUint1
	var x77, x78, x79, x80, x81, x82, x83, x84, x85 uint64
	var x86 FiatPastaFpUint1
	var x87 uint64
	var x88 FiatPastaFpUint1
	var x89 uint64
	var x90 FiatPastaFpUint1
	var x91 uint64
	var x92 FiatPastaFpUint1
	var x93 uint64
	var x94 FiatPastaFpUint1
	var x95 uint64
	var x96 FiatPastaFpUint1
	var x97 uint64
	var x98 FiatPastaFpUint1
	var x99, x100, x101, x102, x103, x104, x105, x106, x107 uint64
	var x108 FiatPastaFpUint1
	var x109 uint64
	var x110 FiatPastaFpUint1
	var x111 uint64
	var x112 FiatPastaFpUint1
	var x113 uint64
	var x114 FiatPastaFpUint1
	var x115 uint64
	var x116 FiatPastaFpUint1
	var x117, x118, x119, x120, x121, x122, x123, x124, x125 uint64
	var x126 FiatPastaFpUint1
	var x127 uint64
	var x128 FiatPastaFpUint1
	var x129 uint64
	var x130 FiatPastaFpUint1
	var x131 uint64
	var x132 FiatPastaFpUint1
	var x133 uint64
	var x134 FiatPastaFpUint1
	var x135 uint64
	var x136 FiatPastaFpUint1
	var x137 uint64
	var x138 FiatPastaFpUint1
	var x139, x140, x141, x142, x143, x144, x145, x146, x147 uint64
	var x148 FiatPastaFpUint1
	var x149 uint64
	var x150 FiatPastaFpUint1
	var x151 uint64
	var x152 FiatPastaFpUint1
	var x153 uint64
	var x154 FiatPastaFpUint1
	var x155 uint64
	var x156 FiatPastaFpUint1
	var x157, x158 uint64
	var x159 FiatPastaFpUint1
	var x160 uint64
	var x161 FiatPastaFpUint1
	var x162 uint64
	var x163 FiatPastaFpUint1
	var x164 uint64
	var x165 FiatPastaFpUint1
	var x166 uint64
	var x167 FiatPastaFpUint1
	var x168, x169, x170, x171 uint64

	x1 = arg1[1]
	x2 = arg1[2]
	x3 = arg1[3]
	x4 = arg1[0]

	FiatPastaFpMulXU64(&x5, &x6, x4, uint64(0x96d41af7b9cb714))
	FiatPastaFpMulXU64(&x7, &x8, x4, uint64(0x7797a99bc3c95d18))
	FiatPastaFpMulXU64(&x9, &x10, x4, uint64(0xd7d30dbd8b0de0e7))
	FiatPastaFpMulXU64(&x11, &x12, x4, uint64(0x8c78ecb30000000f))
	FiatPastaFpAddCarryXU64(&x13, &x14, 0x0, x12, x9)
	FiatPastaFpAddCarryXU64(&x15, &x16, x14, x10, x7)
	FiatPastaFpAddCarryXU64(&x17, &x18, x16, x8, x5)
	FiatPastaFpMulXU64(&x19, &x20, x11, uint64(0x992d30ecffffffff))
	FiatPastaFpMulXU64(&x21, &x22, x19, uint64(0x4000000000000000))
	FiatPastaFpMulXU64(&x23, &x24, x19, uint64(0x224698fc094cf91b))
	FiatPastaFpMulXU64(&x25, &x26, x19, uint64(0x992d30ed00000001))
	FiatPastaFpAddCarryXU64(&x27, &x28, 0x0, x26, x23)
	FiatPastaFpAddCarryXU64(&x29, &x30, 0x0, x11, x25)
	FiatPastaFpAddCarryXU64(&x31, &x32, x30, x13, x27)
	FiatPastaFpAddCarryXU64(&x33, &x34, x32, x15, uint64(x28)+x24)
	FiatPastaFpAddCarryXU64(&x35, &x36, x34, x17, x21)
	FiatPastaFpMulXU64(&x37, &x38, x1, uint64(0x96d41af7b9cb714))
	FiatPastaFpMulXU64(&x39, &x40, x1, uint64(0x7797a99bc3c95d18))
	FiatPastaFpMulXU64(&x41, &x42, x1, uint64(0xd7d30dbd8b0de0e7))
	FiatPastaFpMulXU64(&x43, &x44, x1, uint64(0x8c78ecb30000000f))
	FiatPastaFpAddCarryXU64(&x45, &x46, 0x0, x44, x41)
	FiatPastaFpAddCarryXU64(&x47, &x48, x46, x42, x39)
	FiatPastaFpAddCarryXU64(&x49, &x50, x48, x40, x37)
	FiatPastaFpAddCarryXU64(&x51, &x52, 0x0, x31, x43)
	FiatPastaFpAddCarryXU64(&x53, &x54, x52, x33, x45)
	FiatPastaFpAddCarryXU64(&x55, &x56, x54, x35, x47)
	FiatPastaFpAddCarryXU64(&x57, &x58, x56, (uint64(x36)+(uint64(x18)+x6))+x22, x49)
	FiatPastaFpMulXU64(&x59, &x60, x51, uint64(0x992d30ecffffffff))
	FiatPastaFpMulXU64(&x61, &x62, x59, uint64(0x4000000000000000))
	FiatPastaFpMulXU64(&x63, &x64, x59, uint64(0x224698fc094cf91b))
	FiatPastaFpMulXU64(&x65, &x66, x59, uint64(0x992d30ed00000001))
	FiatPastaFpAddCarryXU64(&x67, &x68, 0x0, x66, x63)
	FiatPastaFpAddCarryXU64(&x69, &x70, 0x0, x51, x65)
	FiatPastaFpAddCarryXU64(&x71, &x72, x70, x53, x67)
	FiatPastaFpAddCarryXU64(&x73, &x74, x72, x55, uint64(x68)+x64)
	FiatPastaFpAddCarryXU64(&x75, &x76, x74, x57, x61)
	FiatPastaFpMulXU64(&x77, &x78, x2, uint64(0x96d41af7b9cb714))
	FiatPastaFpMulXU64(&x79, &x80, x2, uint64(0x7797a99bc3c95d18))
	FiatPastaFpMulXU64(&x81, &x82, x2, uint64(0xd7d30dbd8b0de0e7))
	FiatPastaFpMulXU64(&x83, &x84, x2, uint64(0x8c78ecb30000000f))
	FiatPastaFpAddCarryXU64(&x85, &x86, 0x0, x84, x81)
	FiatPastaFpAddCarryXU64(&x87, &x88, x86, x82, x79)
	FiatPastaFpAddCarryXU64(&x89, &x90, x88, x80, x77)
	FiatPastaFpAddCarryXU64(&x91, &x92, 0x0, x71, x83)
	FiatPastaFpAddCarryXU64(&x93, &x94, x92, x73, x85)
	FiatPastaFpAddCarryXU64(&x95, &x96, x94, x75, x87)
	FiatPastaFpAddCarryXU64(&x97, &x98, x96, (uint64(x76)+(uint64(x58)+(uint64(x50)+x38)))+x62, x89)
	FiatPastaFpMulXU64(&x99, &x100, x91, uint64(0x992d30ecffffffff))
	FiatPastaFpMulXU64(&x101, &x102, x99, uint64(0x4000000000000000))
	FiatPastaFpMulXU64(&x103, &x104, x99, uint64(0x224698fc094cf91b))
	FiatPastaFpMulXU64(&x105, &x106, x99, uint64(0x992d30ed00000001))
	FiatPastaFpAddCarryXU64(&x107, &x108, 0x0, x106, x103)
	FiatPastaFpAddCarryXU64(&x109, &x110, 0x0, x91, x105)
	FiatPastaFpAddCarryXU64(&x111, &x112, x110, x93, x107)
	FiatPastaFpAddCarryXU64(&x113, &x114, x112, x95, uint64(x108)+x104)
	FiatPastaFpAddCarryXU64(&x115, &x116, x114, x97, x101)
	FiatPastaFpMulXU64(&x117, &x118, x3, uint64(0x96d41af7b9cb714))
	FiatPastaFpMulXU64(&x119, &x120, x3, uint64(0x7797a99bc3c95d18))
	FiatPastaFpMulXU64(&x121, &x122, x3, uint64(0xd7d30dbd8b0de0e7))
	FiatPastaFpMulXU64(&x123, &x124, x3, uint64(0x8c78ecb30000000f))
	FiatPastaFpAddCarryXU64(&x125, &x126, 0x0, x124, x121)
	FiatPastaFpAddCarryXU64(&x127, &x128, x126, x122, x119)
	FiatPastaFpAddCarryXU64(&x129, &x130, x128, x120, x117)
	FiatPastaFpAddCarryXU64(&x131, &x132, 0x0, x111, x123)
	FiatPastaFpAddCarryXU64(&x133, &x134, x132, x113, x125)
	FiatPastaFpAddCarryXU64(&x135, &x136, x134, x115, x127)
	FiatPastaFpAddCarryXU64(&x137, &x138, x136, (uint64(x116)+(uint64(x98)+(uint64(x90)+x78)))+x102, x129)
	FiatPastaFpMulXU64(&x139, &x140, x131, uint64(0x992d30ecffffffff))
	FiatPastaFpMulXU64(&x141, &x142, x139, uint64(0x4000000000000000))
	FiatPastaFpMulXU64(&x143, &x144, x139, uint64(0x224698fc094cf91b))
	FiatPastaFpMulXU64(&x145, &x146, x139, uint64(0x992d30ed00000001))
	FiatPastaFpAddCarryXU64(&x147, &x148, 0x0, x146, x143)
	FiatPastaFpAddCarryXU64(&x149, &x150, 0x0, x131, x145)
	FiatPastaFpAddCarryXU64(&x151, &x152, x150, x133, x147)
	FiatPastaFpAddCarryXU64(&x153, &x154, x152, x135, uint64(x148)+x144)
	FiatPastaFpAddCarryXU64(&x155, &x156, x154, x137, x141)
	x157 = (uint64(x156) + (uint64(x138) + (uint64(x130) + x118))) + x142
	FiatPastaFpSubBorrowXU64(&x158, &x159, 0x0, x151, uint64(0x992d30ed00000001))
	FiatPastaFpSubBorrowXU64(&x160, &x161, x159, x153, uint64(0x224698fc094cf91b))
	FiatPastaFpSubBorrowXU64(&x162, &x163, x161, x155, 0x0)
	FiatPastaFpSubBorrowXU64(&x164, &x165, x163, x157, uint64(0x4000000000000000))
	FiatPastaFpSubBorrowXU64(&x166, &x167, x165, 0x0, 0x0)
	FiatPastaFpCmovznzU64(&x168, x167, x158, x151)
	FiatPastaFpCmovznzU64(&x169, x167, x160, x153)
	FiatPastaFpCmovznzU64(&x170, x167, x162, x155)
	FiatPastaFpCmovznzU64(&x171, x167, x164, x157)
	out1[0] = x168
	out1[1] = x169
	out1[2] = x170
	out1[3] = x171
}

/*
 * The function fiat_pasta_fp_nonzero outputs a single non-zero word if the input is non-zero and zero otherwise.
 * Preconditions:
 *   0 ≤ eval arg1 < m
 * Postconditions:
 *   out1 = 0 ↔ eval (from_montgomery arg1) mod m = 0
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 * Output Bounds:
 *   out1: [0x0 ~> 0xffffffffffffffff]
 */
func FiatPastaFpNonZero(out1 *uint64, arg1 [4]uint64) {
	var x1 uint64
	x1 = arg1[0] | (arg1[1] | (arg1[2] | arg1[3]))
	*out1 = x1
}

/*
 * The function fiat_pasta_fp_selectznz is a multi-limb conditional select.
 * Postconditions:
 *   eval out1 = (if arg1 = 0 then eval arg2 else eval arg3)
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 *   arg3: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
func FiatPastaFpSelectZnz(out1 [4]uint64, arg1 FiatPastaFpUint1, arg2, arg3 [4]uint64) {
	var x1, x2, x3, x4 uint64
	FiatPastaFpCmovznzU64(&x1, arg1, arg2[0], arg3[0])
	FiatPastaFpCmovznzU64(&x2, arg1, arg2[1], arg3[1])
	FiatPastaFpCmovznzU64(&x3, arg1, arg2[2], arg3[2])
	FiatPastaFpCmovznzU64(&x4, arg1, arg2[3], arg3[3])

	out1[0] = x1
	out1[1] = x2
	out1[2] = x3
	out1[3] = x4
}

/*
 * The function fiat_pasta_fp_to_bytes serializes a field element NOT in the Montgomery domain to bytes in little-endian order.
 * Preconditions:
 *   0 ≤ eval arg1 < m
 * Postconditions:
 *   out1 = map (λ x, ⌊((eval arg1 mod m) mod 2^(8 * (x + 1))) / 2^(8 * x)⌋) [0..31]
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0x7fffffffffffffff]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0x7f]]
 */
func FiatPastaFpToBytes(out1 [32]uint8, arg1 [4]uint64) {
	var x1, x2, x3, x4 uint64
	var x5 uint8
	var x6 uint64
	var x7 uint8
	var x8 uint64
	var x9 uint8
	var x10 uint64
	var x11 uint8
	var x12 uint64
	var x13 uint8
	var x14 uint64
	var x15 uint8
	var x16 uint64
	var x17, x18, x19 uint8
	var x20 uint64
	var x21 uint8
	var x22 uint64
	var x23 uint8
	var x24 uint64
	var x25 uint8
	var x26 uint64
	var x27 uint8
	var x28 uint64
	var x29 uint8
	var x30 uint64
	var x31, x32, x33 uint8
	var x34 uint64
	var x35 uint8
	var x36 uint64
	var x37 uint8
	var x38 uint64
	var x39 uint8
	var x40 uint64
	var x41 uint8
	var x42 uint64
	var x43 uint8
	var x44 uint64
	var x45, x46, x47 uint8
	var x48 uint64
	var x49 uint8
	var x50 uint64
	var x51 uint8
	var x52 uint64
	var x53 uint8
	var x54 uint64
	var x55 uint8
	var x56 uint64
	var x57 uint8
	var x58 uint64
	var x59, x60 uint8

	x1 = arg1[3]
	x2 = arg1[2]
	x3 = arg1[1]
	x4 = arg1[0]
	x5 = (uint8)(x4 & (0xff))
	x6 = x4 >> 8
	x7 = (uint8)(x6 & (0xff))
	x8 = x6 >> 8
	x9 = (uint8)(x8 & (0xff))
	x10 = x8 >> 8
	x11 = (uint8)(x10 & (0xff))
	x12 = x10 >> 8
	x13 = (uint8)(x12 & (0xff))
	x14 = x12 >> 8
	x15 = (uint8)(x14 & (0xff))
	x16 = x14 >> 8
	x17 = (uint8)(x16 & (0xff))
	x18 = (uint8)(x16 >> 8)
	x19 = (uint8)(x3 & (0xff))
	x20 = x3 >> 8
	x21 = (uint8)(x20 & (0xff))
	x22 = x20 >> 8
	x23 = (uint8)(x22 & (0xff))
	x24 = x22 >> 8
	x25 = (uint8)(x24 & (0xff))
	x26 = x24 >> 8
	x27 = (uint8)(x26 & (0xff))
	x28 = x26 >> 8
	x29 = (uint8)(x28 & (0xff))
	x30 = x28 >> 8
	x31 = (uint8)(x30 & (0xff))
	x32 = (uint8)(x30 >> 8)
	x33 = (uint8)(x2 & (0xff))
	x34 = x2 >> 8
	x35 = (uint8)(x34 & (0xff))
	x36 = x34 >> 8
	x37 = (uint8)(x36 & (0xff))
	x38 = x36 >> 8
	x39 = (uint8)(x38 & (0xff))
	x40 = x38 >> 8
	x41 = (uint8)(x40 & (0xff))
	x42 = x40 >> 8
	x43 = (uint8)(x42 & (0xff))
	x44 = x42 >> 8
	x45 = (uint8)(x44 & (0xff))
	x46 = (uint8)(x44 >> 8)
	x47 = (uint8)(x1 & (0xff))
	x48 = x1 >> 8
	x49 = (uint8)(x48 & (0xff))
	x50 = x48 >> 8
	x51 = (uint8)(x50 & (0xff))
	x52 = x50 >> 8
	x53 = (uint8)(x52 & (0xff))
	x54 = x52 >> 8
	x55 = (uint8)(x54 & (0xff))
	x56 = x54 >> 8
	x57 = (uint8)(x56 & (0xff))
	x58 = x56 >> 8
	x59 = (uint8)(x58 & (0xff))
	x60 = (uint8)(x58 >> 8)
	out1[0] = x5
	out1[1] = x7
	out1[2] = x9
	out1[3] = x11
	out1[4] = x13
	out1[5] = x15
	out1[6] = x17
	out1[7] = x18
	out1[8] = x19
	out1[9] = x21
	out1[10] = x23
	out1[11] = x25
	out1[12] = x27
	out1[13] = x29
	out1[14] = x31
	out1[15] = x32
	out1[16] = x33
	out1[17] = x35
	out1[18] = x37
	out1[19] = x39
	out1[20] = x41
	out1[21] = x43
	out1[22] = x45
	out1[23] = x46
	out1[24] = x47
	out1[25] = x49
	out1[26] = x51
	out1[27] = x53
	out1[28] = x55
	out1[29] = x57
	out1[30] = x59
	out1[31] = x60
}

/*
 * The function fiat_pasta_fp_from_bytes deserializes a field element NOT in the Montgomery domain from bytes in little-endian order.
 * Preconditions:
 *   0 ≤ bytes_eval arg1 < m
 * Postconditions:
 *   eval out1 mod m = bytes_eval arg1 mod m
 *   0 ≤ eval out1 < m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0x7f]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0x7fffffffffffffff]]
 */
func FiatPastaFpFromBytes(out1 [4]uint64, arg1 [32]uint8) {
	var x1, x2, x3, x4, x5, x6, x7 uint64
	var x8 uint8
	var x9, x10, x11, x12, x13, x14, x15 uint64
	var x16 uint8
	var x17, x18, x19, x20, x21, x22, x23 uint64
	var x24 uint8
	var x25, x26, x27, x28, x29, x30, x31 uint64
	var x32 uint8
	var x33, x34, x35, x36, x37, x38, x39, x40, x41, x42, x43, x44, x45, x46, x47, x48, x49, x50, x51, x52, x53, x54, x55, x56, x57, x58, x59, x60 uint64
	x1 = (uint64)(arg1[31]) << 56
	x2 = (uint64)(arg1[30]) << 48
	x3 = (uint64)(arg1[29]) << 40
	x4 = (uint64)(arg1[28]) << 32
	x5 = (uint64)(arg1[27]) << 24
	x6 = (uint64)(arg1[26]) << 16
	x7 = (uint64)(arg1[25]) << 8
	x8 = arg1[24]
	x9 = (uint64)(arg1[23]) << 56
	x10 = (uint64)(arg1[22]) << 48
	x11 = (uint64)(arg1[21]) << 40
	x12 = (uint64)(arg1[20]) << 32
	x13 = (uint64)(arg1[19]) << 24
	x14 = (uint64)(arg1[18]) << 16
	x15 = (uint64)(arg1[17]) << 8
	x16 = arg1[16]
	x17 = (uint64)(arg1[15]) << 56
	x18 = (uint64)(arg1[14]) << 48
	x19 = (uint64)(arg1[13]) << 40
	x20 = (uint64)(arg1[12]) << 32
	x21 = (uint64)(arg1[11]) << 24
	x22 = (uint64)(arg1[10]) << 16
	x23 = (uint64)(arg1[9]) << 8
	x24 = arg1[8]
	x25 = (uint64)(arg1[7]) << 56
	x26 = (uint64)(arg1[6]) << 48
	x27 = (uint64)(arg1[5]) << 40
	x28 = (uint64)(arg1[4]) << 32
	x29 = (uint64)(arg1[3]) << 24
	x30 = (uint64)(arg1[2]) << 16
	x31 = (uint64)(arg1[1]) << 8
	x32 = arg1[0]
	x33 = x31 + (uint64)(x32)
	x34 = x30 + x33
	x35 = x29 + x34
	x36 = x28 + x35
	x37 = x27 + x36
	x38 = x26 + x37
	x39 = x25 + x38
	x40 = x23 + (uint64)(x24)
	x41 = x22 + x40
	x42 = x21 + x41
	x43 = x20 + x42
	x44 = x19 + x43
	x45 = x18 + x44
	x46 = x17 + x45
	x47 = x15 + (uint64)(x16)
	x48 = x14 + x47
	x49 = x13 + x48
	x50 = x12 + x49
	x51 = x11 + x50
	x52 = x10 + x51
	x53 = x9 + x52
	x54 = x7 + (uint64)(x8)
	x55 = x6 + x54
	x56 = x5 + x55
	x57 = x4 + x56
	x58 = x3 + x57
	x59 = x2 + x58
	x60 = x1 + x59
	out1[0] = x39
	out1[1] = x46
	out1[2] = x53
	out1[3] = x60
}

/*
 * The function fiat_pasta_fp_set_one returns the field element one in the Montgomery domain.
 * Postconditions:
 *   eval (from_montgomery out1) mod m = 1 mod m
 *   0 ≤ eval out1 < m
 *
 * Input Bounds:
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
func FiatPastaFpSetOne(out1 *[4]uint64) {
	out1[0] = uint64(0x34786d38fffffffd)
	out1[1] = uint64(0x992c350be41914ad)
	out1[2] = uint64(0xffffffffffffffff)
	out1[3] = uint64(0x3fffffffffffffff)
}

/*
 * The function fiat_pasta_fp_msat returns the saturated represtation of the prime modulus.
 * Postconditions:
 *   twos_complement_eval out1 = m
 *   0 ≤ eval out1 < m
 *
 * Input Bounds:
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
func FiatPastaFpMSat(out1 [5]uint64) {
	out1[0] = uint64(0x992d30ed00000001)
	out1[1] = uint64(0x224698fc094cf91b)
	out1[2] = 0x0
	out1[3] = uint64(0x4000000000000000)
	out1[4] = 0x0
}

/*
 * The function fiat_pasta_fp_divstep_precomp returns the precomputed value for Bernstein-Yang-inversion (in montgomery form).
 * Postconditions:
 *   eval (from_montgomery out1) = ⌊(m - 1) / 2⌋^(if (log2 m) + 1 < 46 then ⌊(49 * ((log2 m) + 1) + 80) / 17⌋ else ⌊(49 * ((log2 m) + 1) + 57) / 17⌋)
 *   0 ≤ eval out1 < m
 *
 * Input Bounds:
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
func FiatPastaFpDivStepPreComp(out1 [4]uint64) {
	out1[0] = uint64(0xeb9f9ebd71876582)
	out1[1] = uint64(0x61d4a765274d339b)
	out1[2] = uint64(0x4bf06d486f0671ed)
	out1[3] = uint64(0x278227fb0b195a26)
}

/*
 * The function fiat_pasta_fp_divstep computes a divstep.
 * Preconditions:
 *   0 ≤ eval arg4 < m
 *   0 ≤ eval arg5 < m
 * Postconditions:
 *   out1 = (if 0 < arg1 ∧ (twos_complement_eval arg3) is odd then 1 - arg1 else 1 + arg1)
 *   twos_complement_eval out2 = (if 0 < arg1 ∧ (twos_complement_eval arg3) is odd then twos_complement_eval arg3 else twos_complement_eval arg2)
 *   twos_complement_eval out3 = (if 0 < arg1 ∧ (twos_complement_eval arg3) is odd then ⌊(twos_complement_eval arg3 - twos_complement_eval arg2) / 2⌋ else ⌊(twos_complement_eval arg3 + (twos_complement_eval arg3 mod 2) * twos_complement_eval arg2) / 2⌋)
 *   eval (from_montgomery out4) mod m = (if 0 < arg1 ∧ (twos_complement_eval arg3) is odd then (2 * eval (from_montgomery arg5)) mod m else (2 * eval (from_montgomery arg4)) mod m)
 *   eval (from_montgomery out5) mod m = (if 0 < arg1 ∧ (twos_complement_eval arg3) is odd then (eval (from_montgomery arg4) - eval (from_montgomery arg4)) mod m else (eval (from_montgomery arg5) + (twos_complement_eval arg3 mod 2) * eval (from_montgomery arg4)) mod m)
 *   0 ≤ eval out5 < m
 *   0 ≤ eval out5 < m
 *   0 ≤ eval out2 < m
 *   0 ≤ eval out3 < m
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0xffffffffffffffff]
 *   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 *   arg3: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 *   arg4: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 *   arg5: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 * Output Bounds:
 *   out1: [0x0 ~> 0xffffffffffffffff]
 *   out2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 *   out3: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 *   out4: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 *   out5: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
func FiatPastaFpDivStep(out1 *uint64, out2, out3 [5]uint64, out4, out5 [4]uint64, arg1 uint64, arg2, arg3 [5]uint64, arg4, arg5 [4]uint64) {
	var x1 uint64
	var x2, x3 FiatPastaFpUint1
	var x4 uint64
	var x5 FiatPastaFpUint1
	var x6, x7, x8, x9, x10, x11, x12 uint64
	var x13 FiatPastaFpUint1
	var x14 uint64
	var x15 FiatPastaFpUint1
	var x16 uint64
	var x17 FiatPastaFpUint1
	var x18 uint64
	var x19 FiatPastaFpUint1
	var x20 uint64
	var x21 FiatPastaFpUint1
	var x22, x23, x24, x25, x26, x27, x28, x29, x30, x31 uint64
	var x32 FiatPastaFpUint1
	var x33 uint64
	var x34 FiatPastaFpUint1
	var x35 uint64
	var x36 FiatPastaFpUint1
	var x37 uint64
	var x38 FiatPastaFpUint1
	var x39 uint64
	var x40 FiatPastaFpUint1
	var x41 uint64
	var x42 FiatPastaFpUint1
	var x43 uint64
	var x44 FiatPastaFpUint1
	var x45 uint64
	var x46 FiatPastaFpUint1
	var x47 uint64
	var x48 FiatPastaFpUint1
	var x49, x50, x51, x52, x53 uint64
	var x54 FiatPastaFpUint1
	var x55 uint64
	var x56 FiatPastaFpUint1
	var x57 uint64
	var x58 FiatPastaFpUint1
	var x59 uint64
	var x60 FiatPastaFpUint1
	var x61, x62 uint64
	var x63 FiatPastaFpUint1
	var x64 uint64
	var x65 FiatPastaFpUint1
	var x66 uint64
	var x67 FiatPastaFpUint1
	var x68 uint64
	var x69 FiatPastaFpUint1
	var x70, x71, x72, x73 uint64
	var x74 FiatPastaFpUint1
	var x75, x76, x77, x78, x79, x80 uint64
	var x81 FiatPastaFpUint1
	var x82 uint64
	var x83 FiatPastaFpUint1
	var x84 uint64
	var x85 FiatPastaFpUint1
	var x86 uint64
	var x87 FiatPastaFpUint1
	var x88 uint64
	var x89 FiatPastaFpUint1
	var x90, x91, x92, x93, x94 uint64
	var x95 FiatPastaFpUint1
	var x96 uint64
	var x97 FiatPastaFpUint1
	var x98 uint64
	var x99 FiatPastaFpUint1
	var x100 uint64
	var x101 FiatPastaFpUint1
	var x102 uint64
	var x103 FiatPastaFpUint1
	var x104 uint64
	var x105 FiatPastaFpUint1
	var x106 uint64
	var x107 FiatPastaFpUint1
	var x108 uint64
	var x109 FiatPastaFpUint1
	var x110 uint64
	var x111 FiatPastaFpUint1
	var x112 uint64
	var x113 FiatPastaFpUint1
	var x114, x115, x116, x117, x118, x119, x120, x121, x122, x123, x124, x125, x126 uint64

	FiatPastaFpAddCarryXU64(&x1, &x2, 0x0, ^arg1, 0x1)
	x3 = (FiatPastaFpUint1)((FiatPastaFpUint1)(x1>>63) & (FiatPastaFpUint1)((arg3[0])&0x1))
	FiatPastaFpAddCarryXU64(&x4, &x5, 0x0, ^arg1, 0x1)
	FiatPastaFpCmovznzU64(&x6, x3, arg1, x4)
	FiatPastaFpCmovznzU64(&x7, x3, arg2[0], arg3[0])
	FiatPastaFpCmovznzU64(&x8, x3, arg2[1], arg3[1])
	FiatPastaFpCmovznzU64(&x9, x3, arg2[2], arg3[2])
	FiatPastaFpCmovznzU64(&x10, x3, arg2[3], arg3[3])
	FiatPastaFpCmovznzU64(&x11, x3, arg2[4], arg3[4])
	FiatPastaFpAddCarryXU64(&x12, &x13, 0x0, 0x1, ^(arg2[0]))
	FiatPastaFpAddCarryXU64(&x14, &x15, x13, 0x0, ^(arg2[1]))
	FiatPastaFpAddCarryXU64(&x16, &x17, x15, 0x0, ^(arg2[2]))
	FiatPastaFpAddCarryXU64(&x18, &x19, x17, 0x0, ^(arg2[3]))
	FiatPastaFpAddCarryXU64(&x20, &x21, x19, 0x0, ^(arg2[4]))
	FiatPastaFpCmovznzU64(&x22, x3, arg3[0], x12)
	FiatPastaFpCmovznzU64(&x23, x3, arg3[1], x14)
	FiatPastaFpCmovznzU64(&x24, x3, arg3[2], x16)
	FiatPastaFpCmovznzU64(&x25, x3, arg3[3], x18)
	FiatPastaFpCmovznzU64(&x26, x3, arg3[4], x20)
	FiatPastaFpCmovznzU64(&x27, x3, arg4[0], arg5[0])
	FiatPastaFpCmovznzU64(&x28, x3, arg4[1], arg5[1])
	FiatPastaFpCmovznzU64(&x29, x3, arg4[2], arg5[2])
	FiatPastaFpCmovznzU64(&x30, x3, arg4[3], arg5[3])
	FiatPastaFpAddCarryXU64(&x31, &x32, 0x0, x27, x27)
	FiatPastaFpAddCarryXU64(&x33, &x34, x32, x28, x28)
	FiatPastaFpAddCarryXU64(&x35, &x36, x34, x29, x29)
	FiatPastaFpAddCarryXU64(&x37, &x38, x36, x30, x30)
	FiatPastaFpSubBorrowXU64(&x39, &x40, 0x0, x31, uint64(0x992d30ed00000001))
	FiatPastaFpSubBorrowXU64(&x41, &x42, x40, x33, uint64(0x224698fc094cf91b))
	FiatPastaFpSubBorrowXU64(&x43, &x44, x42, x35, 0x0)
	FiatPastaFpSubBorrowXU64(&x45, &x46, x44, x37, uint64(0x4000000000000000))
	FiatPastaFpSubBorrowXU64(&x47, &x48, x46, uint64(x38), 0x0)
	x49 = arg4[3]
	x50 = arg4[2]
	x51 = arg4[1]
	x52 = arg4[0]
	FiatPastaFpSubBorrowXU64(&x53, &x54, 0x0, 0x0, x52)
	FiatPastaFpSubBorrowXU64(&x55, &x56, x54, 0x0, x51)
	FiatPastaFpSubBorrowXU64(&x57, &x58, x56, 0x0, x50)
	FiatPastaFpSubBorrowXU64(&x59, &x60, x58, 0x0, x49)
	FiatPastaFpCmovznzU64(&x61, x60, 0x0, uint64(0xffffffffffffffff))
	FiatPastaFpAddCarryXU64(&x62, &x63, 0x0, x53, x61&uint64(0x992d30ed00000001))
	FiatPastaFpAddCarryXU64(&x64, &x65, x63, x55, x61&uint64(0x224698fc094cf91b))
	FiatPastaFpAddCarryXU64(&x66, &x67, x65, x57, 0x0)
	FiatPastaFpAddCarryXU64(&x68, &x69, x67, x59, x61&uint64(0x4000000000000000))
	FiatPastaFpCmovznzU64(&x70, x3, arg5[0], x62)
	FiatPastaFpCmovznzU64(&x71, x3, arg5[1], x64)
	FiatPastaFpCmovznzU64(&x72, x3, arg5[2], x66)
	FiatPastaFpCmovznzU64(&x73, x3, arg5[3], x68)
	x74 = (FiatPastaFpUint1)(x22 & 0x1)
	FiatPastaFpCmovznzU64(&x75, x74, 0x0, x7)
	FiatPastaFpCmovznzU64(&x76, x74, 0x0, x8)
	FiatPastaFpCmovznzU64(&x77, x74, 0x0, x9)
	FiatPastaFpCmovznzU64(&x78, x74, 0x0, x10)
	FiatPastaFpCmovznzU64(&x79, x74, 0x0, x11)
	FiatPastaFpAddCarryXU64(&x80, &x81, 0x0, x22, x75)
	FiatPastaFpAddCarryXU64(&x82, &x83, x81, x23, x76)
	FiatPastaFpAddCarryXU64(&x84, &x85, x83, x24, x77)
	FiatPastaFpAddCarryXU64(&x86, &x87, x85, x25, x78)
	FiatPastaFpAddCarryXU64(&x88, &x89, x87, x26, x79)
	FiatPastaFpCmovznzU64(&x90, x74, 0x0, x27)
	FiatPastaFpCmovznzU64(&x91, x74, 0x0, x28)
	FiatPastaFpCmovznzU64(&x92, x74, 0x0, x29)
	FiatPastaFpCmovznzU64(&x93, x74, 0x0, x30)
	FiatPastaFpAddCarryXU64(&x94, &x95, 0x0, x70, x90)
	FiatPastaFpAddCarryXU64(&x96, &x97, x95, x71, x91)
	FiatPastaFpAddCarryXU64(&x98, &x99, x97, x72, x92)
	FiatPastaFpAddCarryXU64(&x100, &x101, x99, x73, x93)
	FiatPastaFpSubBorrowXU64(&x102, &x103, 0x0, x94, uint64(0x992d30ed00000001))
	FiatPastaFpSubBorrowXU64(&x104, &x105, x103, x96, uint64(0x224698fc094cf91b))
	FiatPastaFpSubBorrowXU64(&x106, &x107, x105, x98, 0x0)
	FiatPastaFpSubBorrowXU64(&x108, &x109, x107, x100, uint64(0x4000000000000000))
	FiatPastaFpSubBorrowXU64(&x110, &x111, x109, uint64(x101), 0x0)
	FiatPastaFpAddCarryXU64(&x112, &x113, 0x0, x6, 0x1)
	x114 = (x80 >> 1) | ((x82 << 63) & uint64(0xffffffffffffffff))
	x115 = (x82 >> 1) | ((x84 << 63) & uint64(0xffffffffffffffff))
	x116 = (x84 >> 1) | ((x86 << 63) & uint64(0xffffffffffffffff))
	x117 = (x86 >> 1) | ((x88 << 63) & uint64(0xffffffffffffffff))
	x118 = (x88 & uint64(0x8000000000000000)) | (x88 >> 1)
	FiatPastaFpCmovznzU64(&x119, x48, x39, x31)
	FiatPastaFpCmovznzU64(&x120, x48, x41, x33)
	FiatPastaFpCmovznzU64(&x121, x48, x43, x35)
	FiatPastaFpCmovznzU64(&x122, x48, x45, x37)
	FiatPastaFpCmovznzU64(&x123, x111, x102, x94)
	FiatPastaFpCmovznzU64(&x124, x111, x104, x96)
	FiatPastaFpCmovznzU64(&x125, x111, x106, x98)
	FiatPastaFpCmovznzU64(&x126, x111, x108, x100)
	*out1 = x112
	out2[0] = x7
	out2[1] = x8
	out2[2] = x9
	out2[3] = x10
	out2[4] = x11
	out3[0] = x114
	out3[1] = x115
	out3[2] = x116
	out3[3] = x117
	out3[4] = x118
	out4[0] = x119
	out4[1] = x120
	out4[2] = x121
	out4[3] = x122
	out5[0] = x123
	out5[1] = x124
	out5[2] = x125
	out5[3] = x126
}

func FiatPastaFpCopy(out *[4]uint64, value [4]uint64) {
	for j := 0; j < 4; j++ {
		out[j] = value[j]
	}
}

func FiatPastaFpPow(out1 *[4]uint64, arg1 [4]uint64, msb_bits []bool, bits_len int) {
	FiatPastaFpSetOne(out1)
	var tmp [4]uint64

	for i := 0; i < bits_len; i++ {
		FiatPastaFpCopy(&tmp, *out1)
		FiatPastaFpSquare(out1, tmp)

		if msb_bits[i] {
			FiatPastaFpCopy(&tmp, *out1)
			FiatPastaFpMul(out1, tmp, arg1)
		}
	}
}

func FiatPastaFpInv(out1 *[4]uint64, arg1 [4]uint64) {
	var PMinus2 = []bool{true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true, false, false, false, true, false, false, true, false, false, false, true, true, false, true, false, false, true, true, false, false, false, true, true, true, true, true, true, false, false, false, false, false, false, true, false, false, true, false, true, false, false, true, true, false, false, true, true, true, true, true, false, false, true, false, false, false, true, true, false, true, true, true, false, false, true, true, false, false, true, false, false, true, false, true, true, false, true, false, false, true, true, false, false, false, false, true, true, true, false, true, true, false, false, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true}
	FiatPastaFpPow(out1, arg1, PMinus2, 255)
}

func FiatPastaFpEquals(x, y [4]uint64) bool {
	var x_minus_y [4]uint64
	FiatPastaFpSub(&x_minus_y, x, y)

	var x_minus_y_nonzero uint64
	FiatPastaFpNonZero(&x_minus_y_nonzero, x_minus_y)
	if x_minus_y_nonzero == 0 {
		return true
	}
	return false
}

func FiatPastaFpEqualsZero(x [4]uint64) bool {
	var x_nonzero uint64
	FiatPastaFpNonZero(&x_nonzero, x)
	if x_nonzero == 0 {
		return true
	}
	return false
}

func FiatPastaFpEqualsOne(x [4]uint64) bool {
	var one [4]uint64
	FiatPastaFpSetOne(&one)

	var x_minus_1 [4]uint64
	FiatPastaFpSub(&x_minus_1, x, one)

	var x_minus_1_nonzero uint64
	FiatPastaFpNonZero(&x_minus_1_nonzero, x_minus_1)
	if x_minus_1_nonzero == 0 {
		return true
	}
	return false
}

func FiatPastaFpLegendRe(arg1 [4]uint64) int {
	var tmp [4]uint64
	FiatPastaFpPow(&tmp, arg1, PMinus1Over2, 254)
	var input_non_zero uint64
	FiatPastaFpNonZero(&input_non_zero, arg1)
	if input_non_zero == 0 {
		return 0
	}
	if FiatPastaFpEqualsOne(tmp) {
		return 1
	}
	return -1
}

func FiatPastaFpSqrt(x *[4]uint64, value [4]uint64) bool {
	if FiatPastaFpEqualsZero(value) {
		for j := 0; j < 4; j++ {
			x[j] = 0
		}
		return true
	}

	var check [4]uint64

	FiatPastaFpPow(&check, value, PMinus1Over2, Pminus1Over2Len)
	if !FiatPastaFpEqualsOne(check) {
		return false
	}

	var one [4]uint64
	FiatPastaFpSetOne(&one)

	v := 32

	z := [4]uint64{0xa28db849bad6dbf0, 0x9083cd03d3b539df, 0xfba6b9ca9dc8448e, 0x3ec928747b89c6da}

	var T_MINUS_ONE_DIV_TWO = []bool{true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true, false, false, false, true, false, false, true, false, false, false, true, true, false, true, false, false, true, true, false, false, false, true, true, true, true, true, true, false, false, false, false, false, false, true, false, false, true, false, true, false, false, true, true, false, false, true, true, true, true, true, false, false, true, false, false, false, true, true, false, true, true, true, false, false, true, true, false, false, true, false, false, true, false, true, true, false, true, false, false, true, true, false, false, false, false, true, true, true, false, true, true, false}
	T_MINUS_ONE_DIV_TWO_LEN := 222

	var w [4]uint64
	FiatPastaFpPow(&w, value, T_MINUS_ONE_DIV_TWO, T_MINUS_ONE_DIV_TWO_LEN)
	FiatPastaFpMul(x, value, w)
	var b [4]uint64
	FiatPastaFpMul(&b, *x, w)

	var b2m, tmp [4]uint64

	for !FiatPastaFpEqualsOne(b) {
		m := 0
		FiatPastaFpCopy(&b2m, b)
		for !FiatPastaFpEqualsOne(b2m) {
			FiatPastaFpCopy(&tmp, b2m)
			FiatPastaFpSquare(&b2m, tmp)
			m = m + 1
		}

		j := v - m - 1

		FiatPastaFpCopy(&w, z)

		for j > 0 {
			FiatPastaFpCopy(&tmp, w)
			FiatPastaFpSquare(&w, tmp)
			j--
		}
		FiatPastaFpSquare(&z, w)
		FiatPastaFpCopy(&tmp, b)
		FiatPastaFpMul(&b, tmp, z)
		FiatPastaFpCopy(&tmp, *x)
		FiatPastaFpMul(x, tmp, w)
		v = m
	}
	return true
}
