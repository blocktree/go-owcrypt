package pasta

type FiatPastaFqUint1 uint8
type FiatPastaFqInt1 int8

/*
 * The function fiat_pasta_fq_addcarryx_u64 is an addition with carry.
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
func FiatPastaFqAddCarryXU64(out1 *uint64, out2 *FiatPastaFqUint1, arg1 FiatPastaFqUint1, arg2, arg3 uint64) {
	var tmp = arg3 + uint64(arg1)
	*out1 = arg2 + tmp

	if (arg2 > *out1) || (arg3 > tmp) == true {
		*out2 = 1
	} else {
		*out2 = 0
	}
}

/*
 * The function fiat_pasta_fq_subborrowx_u64 is a subtraction with borrow.
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
func FiatPastaFqSubBorrowXU64(out1 *uint64, out2 *FiatPastaFqUint1, arg1 FiatPastaFqUint1, arg2, arg3 uint64) {
	var tmp = arg3 + uint64(arg1)
	*out1 = arg2 - tmp
	if (arg2 < *out1) || (arg3 > tmp) {
		*out2 = 1
	} else {
		*out2 = 0
	}
}

/*
 * The function fiat_pasta_fq_mulx_u64 is a multiplication, returning the full double-width result.
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
func FiatPastaFqMulXU64(out1, out2 *uint64, a, b uint64) {
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
 * The function fiat_pasta_fq_cmovznz_u64 is a single-word conditional move.
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
func FiatPastaFqCmovznzU64(out1 *uint64, arg1 FiatPastaFqUint1, arg2, arg3 uint64) {
	var x1 FiatPastaFqUint1
	var x2, x3 uint64
	x1 = arg1
	x2 = uint64(FiatPastaFqInt1(0x0-x1)) & uint64(0xffffffffffffffff)
	x3 = (x2 & arg3) | ((^x2) & arg2)
	*out1 = x3
}

/*
 * The function fiat_pasta_fq_mul multiplies two field elements in the Montgomery domain.
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
func FiatPastaFqMul(out1 *[4]uint64, arg1, arg2 [4]uint64) {
	var x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13 uint64
	var x14 FiatPastaFqUint1
	var x15 uint64
	var x16 FiatPastaFqUint1
	var x17 uint64
	var x18 FiatPastaFqUint1
	var x19, x20, x21, x22, x23, x24, x25, x26, x27, x28 uint64
	var x29 FiatPastaFqUint1
	var x30, x31 uint64
	var x32 FiatPastaFqUint1
	var x33 uint64
	var x34 FiatPastaFqUint1
	var x35 uint64
	var x36 FiatPastaFqUint1
	var x37 uint64
	var x38 FiatPastaFqUint1
	var x39 uint64
	var x40 FiatPastaFqUint1
	var x41, x42, x43, x44, x45, x46, x47, x48, x49 uint64
	var x50 FiatPastaFqUint1
	var x51 uint64
	var x52 FiatPastaFqUint1
	var x53 uint64
	var x54 FiatPastaFqUint1
	var x55, x56 uint64
	var x57 FiatPastaFqUint1
	var x58 uint64
	var x59 FiatPastaFqUint1
	var x60 uint64
	var x61 FiatPastaFqUint1
	var x62 uint64
	var x63 FiatPastaFqUint1
	var x64 uint64
	var x65 FiatPastaFqUint1
	var x66, x67, x68, x69, x70, x71, x72, x73, x74 uint64
	var x75 FiatPastaFqUint1
	var x76, x77 uint64
	var x78 FiatPastaFqUint1
	var x79 uint64
	var x80 FiatPastaFqUint1
	var x81 uint64
	var x82 FiatPastaFqUint1
	var x83 uint64
	var x84 FiatPastaFqUint1
	var x85 uint64
	var x86 FiatPastaFqUint1
	var x87, x88, x89, x90, x91, x92, x93, x94, x95, x96 uint64
	var x97 FiatPastaFqUint1
	var x98 uint64
	var x99 FiatPastaFqUint1
	var x100 uint64
	var x101 FiatPastaFqUint1
	var x102, x103 uint64
	var x104 FiatPastaFqUint1
	var x105 uint64
	var x106 FiatPastaFqUint1
	var x107 uint64
	var x108 FiatPastaFqUint1
	var x109 uint64
	var x110 FiatPastaFqUint1
	var x111 uint64
	var x112 FiatPastaFqUint1
	var x113, x114, x115, x116, x117, x118, x119, x120, x121 uint64
	var x122 FiatPastaFqUint1
	var x123, x124 uint64
	var x125 FiatPastaFqUint1
	var x126 uint64
	var x127 FiatPastaFqUint1
	var x128 uint64
	var x129 FiatPastaFqUint1
	var x130 uint64
	var x131 FiatPastaFqUint1
	var x132 uint64
	var x133 FiatPastaFqUint1
	var x134, x135, x136, x137, x138, x139, x140, x141, x142, x143 uint64
	var x144 FiatPastaFqUint1
	var x145 uint64
	var x146 FiatPastaFqUint1
	var x147 uint64
	var x148 FiatPastaFqUint1
	var x149, x150 uint64
	var x151 FiatPastaFqUint1
	var x152 uint64
	var x153 FiatPastaFqUint1
	var x154 uint64
	var x155 FiatPastaFqUint1
	var x156 uint64
	var x157 FiatPastaFqUint1
	var x158 uint64
	var x159 FiatPastaFqUint1
	var x160, x161, x162, x163, x164, x165, x166, x167, x168 uint64
	var x169 FiatPastaFqUint1
	var x170, x171 uint64
	var x172 FiatPastaFqUint1
	var x173 uint64
	var x174 FiatPastaFqUint1
	var x175 uint64
	var x176 FiatPastaFqUint1
	var x177 uint64
	var x178 FiatPastaFqUint1
	var x179 uint64
	var x180 FiatPastaFqUint1
	var x181, x182 uint64
	var x183 FiatPastaFqUint1
	var x184 uint64
	var x185 FiatPastaFqUint1
	var x186 uint64
	var x187 FiatPastaFqUint1
	var x188 uint64
	var x189 FiatPastaFqUint1
	var x190 uint64
	var x191 FiatPastaFqUint1
	var x192, x193, x194, x195 uint64

	x1 = arg1[1]
	x2 = arg1[2]
	x3 = arg1[3]
	x4 = arg1[0]

	FiatPastaFqMulXU64(&x5, &x6, x4, arg2[3])
	FiatPastaFqMulXU64(&x7, &x8, x4, arg2[2])
	FiatPastaFqMulXU64(&x9, &x10, x4, arg2[1])
	FiatPastaFqMulXU64(&x11, &x12, x4, arg2[0])
	FiatPastaFqAddCarryXU64(&x13, &x14, 0x0, x12, x9)
	FiatPastaFqAddCarryXU64(&x15, &x16, x14, x10, x7)
	FiatPastaFqAddCarryXU64(&x17, &x18, x16, x8, x5)

	x19 = uint64(x18) + x6

	FiatPastaFqMulXU64(&x20, &x21, x11, uint64(0x8c46eb20ffffffff))
	FiatPastaFqMulXU64(&x22, &x23, x20, uint64(0x4000000000000000))
	FiatPastaFqMulXU64(&x24, &x25, x20, uint64(0x224698fc0994a8dd))
	FiatPastaFqMulXU64(&x26, &x27, x20, uint64(0x8c46eb2100000001))
	FiatPastaFqAddCarryXU64(&x28, &x29, 0x0, x27, x24)

	x30 = uint64(x29) + x25

	FiatPastaFqAddCarryXU64(&x31, &x32, 0x0, x11, x26)
	FiatPastaFqAddCarryXU64(&x33, &x34, x32, x13, x28)
	FiatPastaFqAddCarryXU64(&x35, &x36, x34, x15, x30)
	FiatPastaFqAddCarryXU64(&x37, &x38, x36, x17, x22)
	FiatPastaFqAddCarryXU64(&x39, &x40, x38, x19, x23)
	FiatPastaFqMulXU64(&x41, &x42, x1, arg2[3])
	FiatPastaFqMulXU64(&x43, &x44, x1, arg2[2])
	FiatPastaFqMulXU64(&x45, &x46, x1, arg2[1])
	FiatPastaFqMulXU64(&x47, &x48, x1, arg2[0])
	FiatPastaFqAddCarryXU64(&x49, &x50, 0x0, x48, x45)
	FiatPastaFqAddCarryXU64(&x51, &x52, x50, x46, x43)
	FiatPastaFqAddCarryXU64(&x53, &x54, x52, x44, x41)

	x55 = uint64(x54) + x42

	FiatPastaFqAddCarryXU64(&x56, &x57, 0x0, x33, x47)
	FiatPastaFqAddCarryXU64(&x58, &x59, x57, x35, x49)
	FiatPastaFqAddCarryXU64(&x60, &x61, x59, x37, x51)
	FiatPastaFqAddCarryXU64(&x62, &x63, x61, x39, x53)
	FiatPastaFqAddCarryXU64(&x64, &x65, x63, uint64(x40), x55)
	FiatPastaFqMulXU64(&x66, &x67, x56, uint64(0x8c46eb20ffffffff))
	FiatPastaFqMulXU64(&x68, &x69, x66, uint64(0x4000000000000000))
	FiatPastaFqMulXU64(&x70, &x71, x66, uint64(0x224698fc0994a8dd))
	FiatPastaFqMulXU64(&x72, &x73, x66, uint64(0x8c46eb2100000001))
	FiatPastaFqAddCarryXU64(&x74, &x75, 0x0, x73, x70)

	x76 = uint64(x75) + x71

	FiatPastaFqAddCarryXU64(&x77, &x78, 0x0, x56, x72)
	FiatPastaFqAddCarryXU64(&x79, &x80, x78, x58, x74)
	FiatPastaFqAddCarryXU64(&x81, &x82, x80, x60, x76)
	FiatPastaFqAddCarryXU64(&x83, &x84, x82, x62, x68)
	FiatPastaFqAddCarryXU64(&x85, &x86, x84, x64, x69)

	x87 = uint64(x86) + uint64(x65)

	FiatPastaFqMulXU64(&x88, &x89, x2, arg2[3])
	FiatPastaFqMulXU64(&x90, &x91, x2, arg2[2])
	FiatPastaFqMulXU64(&x92, &x93, x2, arg2[1])
	FiatPastaFqMulXU64(&x94, &x95, x2, arg2[0])
	FiatPastaFqAddCarryXU64(&x96, &x97, 0x0, x95, x92)
	FiatPastaFqAddCarryXU64(&x98, &x99, x97, x93, x90)
	FiatPastaFqAddCarryXU64(&x100, &x101, x99, x91, x88)

	x102 = uint64(x101) + x89

	FiatPastaFqAddCarryXU64(&x103, &x104, 0x0, x79, x94)
	FiatPastaFqAddCarryXU64(&x105, &x106, x104, x81, x96)
	FiatPastaFqAddCarryXU64(&x107, &x108, x106, x83, x98)
	FiatPastaFqAddCarryXU64(&x109, &x110, x108, x85, x100)
	FiatPastaFqAddCarryXU64(&x111, &x112, x110, x87, x102)
	FiatPastaFqMulXU64(&x113, &x114, x103, uint64(0x8c46eb20ffffffff))
	FiatPastaFqMulXU64(&x115, &x116, x113, uint64(0x4000000000000000))
	FiatPastaFqMulXU64(&x117, &x118, x113, uint64(0x224698fc0994a8dd))
	FiatPastaFqMulXU64(&x119, &x120, x113, uint64(0x8c46eb2100000001))
	FiatPastaFqAddCarryXU64(&x121, &x122, 0x0, x120, x117)

	x123 = uint64(x122) + x118

	FiatPastaFqAddCarryXU64(&x124, &x125, 0x0, x103, x119)
	FiatPastaFqAddCarryXU64(&x126, &x127, x125, x105, x121)
	FiatPastaFqAddCarryXU64(&x128, &x129, x127, x107, x123)
	FiatPastaFqAddCarryXU64(&x130, &x131, x129, x109, x115)
	FiatPastaFqAddCarryXU64(&x132, &x133, x131, x111, x116)

	x134 = uint64(x133) + uint64(x112)

	FiatPastaFqMulXU64(&x135, &x136, x3, arg2[3])
	FiatPastaFqMulXU64(&x137, &x138, x3, arg2[2])
	FiatPastaFqMulXU64(&x139, &x140, x3, arg2[1])
	FiatPastaFqMulXU64(&x141, &x142, x3, arg2[0])
	FiatPastaFqAddCarryXU64(&x143, &x144, 0x0, x142, x139)
	FiatPastaFqAddCarryXU64(&x145, &x146, x144, x140, x137)
	FiatPastaFqAddCarryXU64(&x147, &x148, x146, x138, x135)

	x149 = uint64(x148) + x136

	FiatPastaFqAddCarryXU64(&x150, &x151, 0x0, x126, x141)
	FiatPastaFqAddCarryXU64(&x152, &x153, x151, x128, x143)
	FiatPastaFqAddCarryXU64(&x154, &x155, x153, x130, x145)
	FiatPastaFqAddCarryXU64(&x156, &x157, x155, x132, x147)
	FiatPastaFqAddCarryXU64(&x158, &x159, x157, x134, x149)
	FiatPastaFqMulXU64(&x160, &x161, x150, uint64(0x8c46eb20ffffffff))
	FiatPastaFqMulXU64(&x162, &x163, x160, uint64(0x4000000000000000))
	FiatPastaFqMulXU64(&x164, &x165, x160, uint64(0x224698fc0994a8dd))
	FiatPastaFqMulXU64(&x166, &x167, x160, uint64(0x8c46eb2100000001))
	FiatPastaFqAddCarryXU64(&x168, &x169, 0x0, x167, x164)

	x170 = uint64(x169) + x165

	FiatPastaFqAddCarryXU64(&x171, &x172, 0x0, x150, x166)
	FiatPastaFqAddCarryXU64(&x173, &x174, x172, x152, x168)
	FiatPastaFqAddCarryXU64(&x175, &x176, x174, x154, x170)
	FiatPastaFqAddCarryXU64(&x177, &x178, x176, x156, x162)
	FiatPastaFqAddCarryXU64(&x179, &x180, x178, x158, x163)

	x181 = uint64(x180) + uint64(x159)

	FiatPastaFqSubBorrowXU64(&x182, &x183, 0x0, x173, uint64(0x8c46eb2100000001))
	FiatPastaFqSubBorrowXU64(&x184, &x185, x183, x175, uint64(0x224698fc0994a8dd))
	FiatPastaFqSubBorrowXU64(&x186, &x187, x185, x177, uint64(0x0))
	FiatPastaFqSubBorrowXU64(&x188, &x189, x187, x179, uint64(0x4000000000000000))
	FiatPastaFqSubBorrowXU64(&x190, &x191, x189, x181, uint64(0x0))
	FiatPastaFqCmovznzU64(&x192, x191, x182, x173)
	FiatPastaFqCmovznzU64(&x193, x191, x184, x175)
	FiatPastaFqCmovznzU64(&x194, x191, x186, x177)
	FiatPastaFqCmovznzU64(&x195, x191, x188, x179)

	out1[0] = x192
	out1[1] = x193
	out1[2] = x194
	out1[3] = x195
}

/*
 * The function fiat_pasta_fq_square squares a field element in the Montgomery domain.
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
func FiatPastaFqSquare(out1 *[4]uint64, arg1 [4]uint64) {
	var x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13 uint64
	var x14 FiatPastaFqUint1
	var x15 uint64
	var x16 FiatPastaFqUint1
	var x17 uint64
	var x18 FiatPastaFqUint1
	var x19, x20, x21, x22, x23, x24, x25, x26, x27, x28 uint64
	var x29 FiatPastaFqUint1
	var x30, x31 uint64
	var x32 FiatPastaFqUint1
	var x33 uint64
	var x34 FiatPastaFqUint1
	var x35 uint64
	var x36 FiatPastaFqUint1
	var x37 uint64
	var x38 FiatPastaFqUint1
	var x39 uint64
	var x40 FiatPastaFqUint1
	var x41, x42, x43, x44, x45, x46, x47, x48, x49 uint64
	var x50 FiatPastaFqUint1
	var x51 uint64
	var x52 FiatPastaFqUint1
	var x53 uint64
	var x54 FiatPastaFqUint1
	var x55, x56 uint64
	var x57 FiatPastaFqUint1
	var x58 uint64
	var x59 FiatPastaFqUint1
	var x60 uint64
	var x61 FiatPastaFqUint1
	var x62 uint64
	var x63 FiatPastaFqUint1
	var x64 uint64
	var x65 FiatPastaFqUint1
	var x66, x67, x68, x69, x70, x71, x72, x73, x74 uint64
	var x75 FiatPastaFqUint1
	var x76, x77 uint64
	var x78 FiatPastaFqUint1
	var x79 uint64
	var x80 FiatPastaFqUint1
	var x81 uint64
	var x82 FiatPastaFqUint1
	var x83 uint64
	var x84 FiatPastaFqUint1
	var x85 uint64
	var x86 FiatPastaFqUint1
	var x87, x88, x89, x90, x91, x92, x93, x94, x95, x96 uint64
	var x97 FiatPastaFqUint1
	var x98 uint64
	var x99 FiatPastaFqUint1
	var x100 uint64
	var x101 FiatPastaFqUint1
	var x102, x103 uint64
	var x104 FiatPastaFqUint1
	var x105 uint64
	var x106 FiatPastaFqUint1
	var x107 uint64
	var x108 FiatPastaFqUint1
	var x109 uint64
	var x110 FiatPastaFqUint1
	var x111 uint64
	var x112 FiatPastaFqUint1
	var x113, x114, x115, x116, x117, x118, x119, x120, x121 uint64
	var x122 FiatPastaFqUint1
	var x123, x124 uint64
	var x125 FiatPastaFqUint1
	var x126 uint64
	var x127 FiatPastaFqUint1
	var x128 uint64
	var x129 FiatPastaFqUint1
	var x130 uint64
	var x131 FiatPastaFqUint1
	var x132 uint64
	var x133 FiatPastaFqUint1
	var x134, x135, x136, x137, x138, x139, x140, x141, x142, x143 uint64
	var x144 FiatPastaFqUint1
	var x145 uint64
	var x146 FiatPastaFqUint1
	var x147 uint64
	var x148 FiatPastaFqUint1
	var x149, x150 uint64
	var x151 FiatPastaFqUint1
	var x152 uint64
	var x153 FiatPastaFqUint1
	var x154 uint64
	var x155 FiatPastaFqUint1
	var x156 uint64
	var x157 FiatPastaFqUint1
	var x158 uint64
	var x159 FiatPastaFqUint1
	var x160, x161, x162, x163, x164, x165, x166, x167, x168 uint64
	var x169 FiatPastaFqUint1
	var x170, x171 uint64
	var x172 FiatPastaFqUint1
	var x173 uint64
	var x174 FiatPastaFqUint1
	var x175 uint64
	var x176 FiatPastaFqUint1
	var x177 uint64
	var x178 FiatPastaFqUint1
	var x179 uint64
	var x180 FiatPastaFqUint1
	var x181, x182 uint64
	var x183 FiatPastaFqUint1
	var x184 uint64
	var x185 FiatPastaFqUint1
	var x186 uint64
	var x187 FiatPastaFqUint1
	var x188 uint64
	var x189 FiatPastaFqUint1
	var x190 uint64
	var x191 FiatPastaFqUint1
	var x192, x193, x194, x195 uint64

	x1 = arg1[1]
	x2 = arg1[2]
	x3 = arg1[3]
	x4 = arg1[0]

	FiatPastaFqMulXU64(&x5, &x6, x4, arg1[3])
	FiatPastaFqMulXU64(&x7, &x8, x4, arg1[2])
	FiatPastaFqMulXU64(&x9, &x10, x4, arg1[1])
	FiatPastaFqMulXU64(&x11, &x12, x4, arg1[0])
	FiatPastaFqAddCarryXU64(&x13, &x14, 0x0, x12, x9)
	FiatPastaFqAddCarryXU64(&x15, &x16, x14, x10, x7)
	FiatPastaFqAddCarryXU64(&x17, &x18, x16, x8, x5)

	x19 = uint64(x18) + x6

	FiatPastaFqMulXU64(&x20, &x21, x11, uint64(0x8c46eb20ffffffff))
	FiatPastaFqMulXU64(&x22, &x23, x20, uint64(0x4000000000000000))
	FiatPastaFqMulXU64(&x24, &x25, x20, uint64(0x224698fc0994a8dd))
	FiatPastaFqMulXU64(&x26, &x27, x20, uint64(0x8c46eb2100000001))
	FiatPastaFqAddCarryXU64(&x28, &x29, 0x0, x27, x24)

	x30 = uint64(x29) + x25

	FiatPastaFqAddCarryXU64(&x31, &x32, 0x0, x11, x26)
	FiatPastaFqAddCarryXU64(&x33, &x34, x32, x13, x28)
	FiatPastaFqAddCarryXU64(&x35, &x36, x34, x15, x30)
	FiatPastaFqAddCarryXU64(&x37, &x38, x36, x17, x22)
	FiatPastaFqAddCarryXU64(&x39, &x40, x38, x19, x23)
	FiatPastaFqMulXU64(&x41, &x42, x1, arg1[3])
	FiatPastaFqMulXU64(&x43, &x44, x1, arg1[2])
	FiatPastaFqMulXU64(&x45, &x46, x1, arg1[1])
	FiatPastaFqMulXU64(&x47, &x48, x1, arg1[0])
	FiatPastaFqAddCarryXU64(&x49, &x50, 0x0, x48, x45)
	FiatPastaFqAddCarryXU64(&x51, &x52, x50, x46, x43)
	FiatPastaFqAddCarryXU64(&x53, &x54, x52, x44, x41)

	x55 = uint64(x54) + x42

	FiatPastaFqAddCarryXU64(&x56, &x57, 0x0, x33, x47)
	FiatPastaFqAddCarryXU64(&x58, &x59, x57, x35, x49)
	FiatPastaFqAddCarryXU64(&x60, &x61, x59, x37, x51)
	FiatPastaFqAddCarryXU64(&x62, &x63, x61, x39, x53)
	FiatPastaFqAddCarryXU64(&x64, &x65, x63, uint64(x40), x55)
	FiatPastaFqMulXU64(&x66, &x67, x56, uint64(0x8c46eb20ffffffff))
	FiatPastaFqMulXU64(&x68, &x69, x66, uint64(0x4000000000000000))
	FiatPastaFqMulXU64(&x70, &x71, x66, uint64(0x224698fc0994a8dd))
	FiatPastaFqMulXU64(&x72, &x73, x66, uint64(0x8c46eb2100000001))
	FiatPastaFqAddCarryXU64(&x74, &x75, 0x0, x73, x70)

	x76 = uint64(x75) + x71

	FiatPastaFqAddCarryXU64(&x77, &x78, 0x0, x56, x72)
	FiatPastaFqAddCarryXU64(&x79, &x80, x78, x58, x74)
	FiatPastaFqAddCarryXU64(&x81, &x82, x80, x60, x76)
	FiatPastaFqAddCarryXU64(&x83, &x84, x82, x62, x68)
	FiatPastaFqAddCarryXU64(&x85, &x86, x84, x64, x69)

	x87 = uint64(x86) + uint64(x65)

	FiatPastaFqMulXU64(&x88, &x89, x2, arg1[3])
	FiatPastaFqMulXU64(&x90, &x91, x2, arg1[2])
	FiatPastaFqMulXU64(&x92, &x93, x2, arg1[1])
	FiatPastaFqMulXU64(&x94, &x95, x2, arg1[0])
	FiatPastaFqAddCarryXU64(&x96, &x97, 0x0, x95, x92)
	FiatPastaFqAddCarryXU64(&x98, &x99, x97, x93, x90)
	FiatPastaFqAddCarryXU64(&x100, &x101, x99, x91, x88)

	x102 = uint64(x101) + x89

	FiatPastaFqAddCarryXU64(&x103, &x104, 0x0, x79, x94)
	FiatPastaFqAddCarryXU64(&x105, &x106, x104, x81, x96)
	FiatPastaFqAddCarryXU64(&x107, &x108, x106, x83, x98)
	FiatPastaFqAddCarryXU64(&x109, &x110, x108, x85, x100)
	FiatPastaFqAddCarryXU64(&x111, &x112, x110, x87, x102)
	FiatPastaFqMulXU64(&x113, &x114, x103, uint64(0x8c46eb20ffffffff))
	FiatPastaFqMulXU64(&x115, &x116, x113, uint64(0x4000000000000000))
	FiatPastaFqMulXU64(&x117, &x118, x113, uint64(0x224698fc0994a8dd))
	FiatPastaFqMulXU64(&x119, &x120, x113, uint64(0x8c46eb2100000001))
	FiatPastaFqAddCarryXU64(&x121, &x122, 0x0, x120, x117)

	x123 = uint64(x122) + x118

	FiatPastaFqAddCarryXU64(&x124, &x125, 0x0, x103, x119)
	FiatPastaFqAddCarryXU64(&x126, &x127, x125, x105, x121)
	FiatPastaFqAddCarryXU64(&x128, &x129, x127, x107, x123)
	FiatPastaFqAddCarryXU64(&x130, &x131, x129, x109, x115)
	FiatPastaFqAddCarryXU64(&x132, &x133, x131, x111, x116)

	x134 = uint64(x133) + uint64(x112)

	FiatPastaFqMulXU64(&x135, &x136, x3, arg1[3])
	FiatPastaFqMulXU64(&x137, &x138, x3, arg1[2])
	FiatPastaFqMulXU64(&x139, &x140, x3, arg1[1])
	FiatPastaFqMulXU64(&x141, &x142, x3, arg1[0])
	FiatPastaFqAddCarryXU64(&x143, &x144, 0x0, x142, x139)
	FiatPastaFqAddCarryXU64(&x145, &x146, x144, x140, x137)
	FiatPastaFqAddCarryXU64(&x147, &x148, x146, x138, x135)

	x149 = uint64(x148) + x136

	FiatPastaFqAddCarryXU64(&x150, &x151, 0x0, x126, x141)
	FiatPastaFqAddCarryXU64(&x152, &x153, x151, x128, x143)
	FiatPastaFqAddCarryXU64(&x154, &x155, x153, x130, x145)
	FiatPastaFqAddCarryXU64(&x156, &x157, x155, x132, x147)
	FiatPastaFqAddCarryXU64(&x158, &x159, x157, x134, x149)
	FiatPastaFqMulXU64(&x160, &x161, x150, uint64(0x8c46eb20ffffffff))
	FiatPastaFqMulXU64(&x162, &x163, x160, uint64(0x4000000000000000))
	FiatPastaFqMulXU64(&x164, &x165, x160, uint64(0x224698fc0994a8dd))
	FiatPastaFqMulXU64(&x166, &x167, x160, uint64(0x8c46eb2100000001))
	FiatPastaFqAddCarryXU64(&x168, &x169, 0x0, x167, x164)

	x170 = uint64(x169) + x165

	FiatPastaFqAddCarryXU64(&x171, &x172, 0x0, x150, x166)
	FiatPastaFqAddCarryXU64(&x173, &x174, x172, x152, x168)
	FiatPastaFqAddCarryXU64(&x175, &x176, x174, x154, x170)
	FiatPastaFqAddCarryXU64(&x177, &x178, x176, x156, x162)
	FiatPastaFqAddCarryXU64(&x179, &x180, x178, x158, x163)

	x181 = uint64(x180) + uint64(x159)

	FiatPastaFqSubBorrowXU64(&x182, &x183, 0x0, x173, uint64(0x8c46eb2100000001))
	FiatPastaFqSubBorrowXU64(&x184, &x185, x183, x175, uint64(0x224698fc0994a8dd))
	FiatPastaFqSubBorrowXU64(&x186, &x187, x185, x177, uint64(0x0))
	FiatPastaFqSubBorrowXU64(&x188, &x189, x187, x179, uint64(0x4000000000000000))
	FiatPastaFqSubBorrowXU64(&x190, &x191, x189, x181, uint64(0x0))
	FiatPastaFqCmovznzU64(&x192, x191, x182, x173)
	FiatPastaFqCmovznzU64(&x193, x191, x184, x175)
	FiatPastaFqCmovznzU64(&x194, x191, x186, x177)
	FiatPastaFqCmovznzU64(&x195, x191, x188, x179)

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
func FiatPastaFqAdd(out1 *[4]uint64, arg1, arg2 [4]uint64) {
	var x1 uint64
	var x2 FiatPastaFqUint1
	var x3 uint64
	var x4 FiatPastaFqUint1
	var x5 uint64
	var x6 FiatPastaFqUint1
	var x7 uint64
	var x8 FiatPastaFqUint1
	var x9 uint64
	var x10 FiatPastaFqUint1
	var x11 uint64
	var x12 FiatPastaFqUint1
	var x13 uint64
	var x14 FiatPastaFqUint1
	var x15 uint64
	var x16 FiatPastaFqUint1
	var x17 uint64
	var x18 FiatPastaFqUint1
	var x19 uint64
	var x20 uint64
	var x21 uint64
	var x22 uint64

	FiatPastaFqAddCarryXU64(&x1, &x2, 0x0, arg1[0], arg2[0])
	FiatPastaFqAddCarryXU64(&x3, &x4, x2, arg1[1], arg2[1])
	FiatPastaFqAddCarryXU64(&x5, &x6, x4, arg1[2], arg2[2])
	FiatPastaFqAddCarryXU64(&x7, &x8, x6, arg1[3], arg2[3])
	FiatPastaFqSubBorrowXU64(&x9, &x10, 0x0, x1, uint64(0x8c46eb2100000001))
	FiatPastaFqSubBorrowXU64(&x11, &x12, x10, x3, uint64(0x224698fc0994a8dd))
	FiatPastaFqSubBorrowXU64(&x13, &x14, x12, x5, 0x0)
	FiatPastaFqSubBorrowXU64(&x15, &x16, x14, x7, uint64(0x4000000000000000))
	FiatPastaFqSubBorrowXU64(&x17, &x18, x16, uint64(x8), 0x0)
	FiatPastaFqCmovznzU64(&x19, x18, x9, x1)
	FiatPastaFqCmovznzU64(&x20, x18, x11, x3)
	FiatPastaFqCmovznzU64(&x21, x18, x13, x5)
	FiatPastaFqCmovznzU64(&x22, x18, x15, x7)
	out1[0] = x19
	out1[1] = x20
	out1[2] = x21
	out1[3] = x22
}

/*
 * The function fiat_pasta_fq_sub subtracts two field elements in the Montgomery domain.
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
func FiatPastaFqSub(out1 *[4]uint64, arg1, arg2 [4]uint64) {
	var x1 uint64
	var x2 FiatPastaFqUint1
	var x3 uint64
	var x4 FiatPastaFqUint1
	var x5 uint64
	var x6 FiatPastaFqUint1
	var x7 uint64
	var x8 FiatPastaFqUint1
	var x9, x10 uint64
	var x11 FiatPastaFqUint1
	var x12 uint64
	var x13 FiatPastaFqUint1
	var x14 uint64
	var x15 FiatPastaFqUint1
	var x16 uint64
	var x17 FiatPastaFqUint1

	FiatPastaFqSubBorrowXU64(&x1, &x2, 0x0, arg1[0], arg2[0])
	FiatPastaFqSubBorrowXU64(&x3, &x4, x2, arg1[1], arg2[1])
	FiatPastaFqSubBorrowXU64(&x5, &x6, x4, arg1[2], arg2[2])
	FiatPastaFqSubBorrowXU64(&x7, &x8, x6, arg1[3], arg2[3])
	FiatPastaFqCmovznzU64(&x9, x8, 0x0, uint64(0xffffffffffffffff))
	FiatPastaFqAddCarryXU64(&x10, &x11, 0x0, x1, x9&uint64(0x8c46eb2100000001))
	FiatPastaFqAddCarryXU64(&x12, &x13, x11, x3, x9&uint64(0x224698fc0994a8dd))
	FiatPastaFqAddCarryXU64(&x14, &x15, x13, x5, uint64(0x0))
	FiatPastaFqAddCarryXU64(&x16, &x17, x15, x7, x9&uint64(0x4000000000000000))

	out1[0] = x10
	out1[1] = x12
	out1[2] = x14
	out1[3] = x16
}

/*
 * The function fiat_pasta_fq_opp negates a field element in the Montgomery domain.
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
func FiatPastaFqOpp(out1 *[4]uint64, arg1 [4]uint64) {
	var x1 uint64
	var x2 FiatPastaFqUint1
	var x3 uint64
	var x4 FiatPastaFqUint1
	var x5 uint64
	var x6 FiatPastaFqUint1
	var x7 uint64
	var x8 FiatPastaFqUint1
	var x9, x10 uint64
	var x11 FiatPastaFqUint1
	var x12 uint64
	var x13 FiatPastaFqUint1
	var x14 uint64
	var x15 FiatPastaFqUint1
	var x16 uint64
	var x17 FiatPastaFqUint1

	FiatPastaFqSubBorrowXU64(&x1, &x2, 0x0, 0x0, arg1[0])
	FiatPastaFqSubBorrowXU64(&x3, &x4, x2, 0x0, arg1[1])
	FiatPastaFqSubBorrowXU64(&x5, &x6, x4, 0x0, arg1[2])
	FiatPastaFqSubBorrowXU64(&x7, &x8, x6, 0x0, arg1[3])
	FiatPastaFqCmovznzU64(&x9, x8, 0x0, uint64(0xffffffffffffffff))
	FiatPastaFqAddCarryXU64(&x10, &x11, 0x0, x1, x9&uint64(0x8c46eb2100000001))
	FiatPastaFqAddCarryXU64(&x12, &x13, x11, x3, x9&uint64(0x224698fc0994a8dd))
	FiatPastaFqAddCarryXU64(&x14, &x15, x13, x5, uint64(0x0))
	FiatPastaFqAddCarryXU64(&x16, &x17, x15, x7, x9&uint64(0x4000000000000000))

	out1[0] = x10
	out1[1] = x12
	out1[2] = x14
	out1[3] = x16
}

/*
 * The function fiat_pasta_fq_from_montgomery translates a field element out of the Montgomery domain.
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
func FiatPastaFqFromMontgomery(out1 *[4]uint64, arg1 [4]uint64) {
	var x1, x2, x3, x4, x5, x6, x7, x8, x9, x10 uint64
	var x11 FiatPastaFqUint1
	var x12 uint64
	var x13 FiatPastaFqUint1
	var x14 uint64
	var x15 FiatPastaFqUint1
	var x16 uint64
	var x17 FiatPastaFqUint1
	var x18, x19, x20, x21, x22, x23, x24, x25, x26 uint64
	var x27 FiatPastaFqUint1
	var x28 uint64
	var x29 FiatPastaFqUint1
	var x30 uint64
	var x31 FiatPastaFqUint1
	var x32 uint64
	var x33 FiatPastaFqUint1
	var x34 uint64
	var x35 FiatPastaFqUint1
	var x36 uint64
	var x37 FiatPastaFqUint1
	var x38 uint64
	var x39 FiatPastaFqUint1
	var x40 uint64
	var x41 FiatPastaFqUint1
	var x42, x43, x44, x45, x46, x47, x48, x49, x50 uint64
	var x51 FiatPastaFqUint1
	var x52 uint64
	var x53 FiatPastaFqUint1
	var x54 uint64
	var x55 FiatPastaFqUint1
	var x56 uint64
	var x57 FiatPastaFqUint1
	var x58 uint64
	var x59 FiatPastaFqUint1
	var x60 uint64
	var x61 FiatPastaFqUint1
	var x62 uint64
	var x63 FiatPastaFqUint1
	var x64 uint64
	var x65 FiatPastaFqUint1
	var x66, x67, x68, x69, x70, x71, x72, x73, x74 uint64
	var x75 FiatPastaFqUint1
	var x76 uint64
	var x77 FiatPastaFqUint1
	var x78 uint64
	var x79 FiatPastaFqUint1
	var x80 uint64
	var x81 FiatPastaFqUint1
	var x82 uint64
	var x83 FiatPastaFqUint1
	var x84, x85 uint64
	var x86 FiatPastaFqUint1
	var x87 uint64
	var x88 FiatPastaFqUint1
	var x89 uint64
	var x90 FiatPastaFqUint1
	var x91 uint64
	var x92 FiatPastaFqUint1
	var x93 uint64
	var x94 FiatPastaFqUint1
	var x95, x96, x97, x98 uint64

	x1 = arg1[0]

	FiatPastaFqMulXU64(&x2, &x3, x1, uint64(0x8c46eb20ffffffff))
	FiatPastaFqMulXU64(&x4, &x5, x2, uint64(0x4000000000000000))
	FiatPastaFqMulXU64(&x6, &x7, x2, uint64(0x224698fc0994a8dd))
	FiatPastaFqMulXU64(&x8, &x9, x2, uint64(0x8c46eb2100000001))
	FiatPastaFqAddCarryXU64(&x10, &x11, 0x0, x9, x6)
	FiatPastaFqAddCarryXU64(&x12, &x13, 0x0, x1, x8)
	FiatPastaFqAddCarryXU64(&x14, &x15, x13, 0x0, x10)
	FiatPastaFqAddCarryXU64(&x16, &x17, 0x0, x14, arg1[1])
	FiatPastaFqMulXU64(&x18, &x19, x16, uint64(0x8c46eb20ffffffff))
	FiatPastaFqMulXU64(&x20, &x21, x18, uint64(0x4000000000000000))
	FiatPastaFqMulXU64(&x22, &x23, x18, uint64(0x224698fc0994a8dd))
	FiatPastaFqMulXU64(&x24, &x25, x18, uint64(0x8c46eb2100000001))
	FiatPastaFqAddCarryXU64(&x26, &x27, 0x0, x25, x22)
	FiatPastaFqAddCarryXU64(&x28, &x29, 0x0, x16, x24)
	FiatPastaFqAddCarryXU64(&x30, &x31, x29, uint64(x17)+(uint64(x15)+(uint64(x11)+x7)), x26)
	FiatPastaFqAddCarryXU64(&x32, &x33, x31, x4, uint64(x27)+x23)
	FiatPastaFqAddCarryXU64(&x34, &x35, x33, x5, x20)
	FiatPastaFqAddCarryXU64(&x36, &x37, 0x0, x30, arg1[2])
	FiatPastaFqAddCarryXU64(&x38, &x39, x37, x32, 0x0)
	FiatPastaFqAddCarryXU64(&x40, &x41, x39, x34, 0x0)
	FiatPastaFqMulXU64(&x42, &x43, x36, uint64(0x8c46eb20ffffffff))
	FiatPastaFqMulXU64(&x44, &x45, x42, uint64(0x4000000000000000))
	FiatPastaFqMulXU64(&x46, &x47, x42, uint64(0x224698fc0994a8dd))
	FiatPastaFqMulXU64(&x48, &x49, x42, uint64(0x8c46eb2100000001))
	FiatPastaFqAddCarryXU64(&x50, &x51, 0x0, x49, x46)
	FiatPastaFqAddCarryXU64(&x52, &x53, 0x0, x36, x48)
	FiatPastaFqAddCarryXU64(&x54, &x55, x53, x38, x50)
	FiatPastaFqAddCarryXU64(&x56, &x57, x55, x40, uint64(x51)+x47)
	FiatPastaFqAddCarryXU64(&x58, &x59, x57, uint64(x41)+(uint64(x35)+x21), x44)
	FiatPastaFqAddCarryXU64(&x60, &x61, 0x0, x54, arg1[3])
	FiatPastaFqAddCarryXU64(&x62, &x63, x61, x56, 0x0)
	FiatPastaFqAddCarryXU64(&x64, &x65, x63, x58, 0x0)
	FiatPastaFqMulXU64(&x66, &x67, x60, uint64(0x8c46eb20ffffffff))
	FiatPastaFqMulXU64(&x68, &x69, x66, uint64(0x4000000000000000))
	FiatPastaFqMulXU64(&x70, &x71, x66, uint64(0x224698fc0994a8dd))
	FiatPastaFqMulXU64(&x72, &x73, x66, uint64(0x8c46eb2100000001))
	FiatPastaFqAddCarryXU64(&x74, &x75, 0x0, x73, x70)
	FiatPastaFqAddCarryXU64(&x76, &x77, 0x0, x60, x72)
	FiatPastaFqAddCarryXU64(&x78, &x79, x77, x62, x74)
	FiatPastaFqAddCarryXU64(&x80, &x81, x79, x64, uint64(x75)+x71)
	FiatPastaFqAddCarryXU64(&x82, &x83, x81, uint64(x65)+(uint64(x59)+x45), x68)
	x84 = uint64(x83) + x69
	FiatPastaFqSubBorrowXU64(&x85, &x86, 0x0, x78, uint64(0x8c46eb2100000001))
	FiatPastaFqSubBorrowXU64(&x87, &x88, x86, x80, uint64(0x224698fc0994a8dd))
	FiatPastaFqSubBorrowXU64(&x89, &x90, x88, x82, 0x0)
	FiatPastaFqSubBorrowXU64(&x91, &x92, x90, x84, uint64(0x4000000000000000))
	FiatPastaFqSubBorrowXU64(&x93, &x94, x92, 0x0, 0x0)
	FiatPastaFqCmovznzU64(&x95, x94, x85, x78)
	FiatPastaFqCmovznzU64(&x96, x94, x87, x80)
	FiatPastaFqCmovznzU64(&x97, x94, x89, x82)
	FiatPastaFqCmovznzU64(&x98, x94, x91, x84)
	out1[0] = x95
	out1[1] = x96
	out1[2] = x97
	out1[3] = x98
}

/*
 * The function fiat_pasta_fq_to_montgomery translates a field element into the Montgomery domain.
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
func FiatPastaFqToMontgomery(out1 *[4]uint64, arg1 [4]uint64) {
	var x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13 uint64
	var x14 FiatPastaFqUint1
	var x15 uint64
	var x16 FiatPastaFqUint1
	var x17 uint64
	var x18 FiatPastaFqUint1
	var x19, x20, x21, x22, x23, x24, x25, x26, x27 uint64
	var x28 FiatPastaFqUint1
	var x29 uint64
	var x30 FiatPastaFqUint1
	var x31 uint64
	var x32 FiatPastaFqUint1
	var x33 uint64
	var x34 FiatPastaFqUint1
	var x35 uint64
	var x36 FiatPastaFqUint1
	var x37, x38, x39, x40, x41, x42, x43, x44, x45 uint64
	var x46 FiatPastaFqUint1
	var x47 uint64
	var x48 FiatPastaFqUint1
	var x49 uint64
	var x50 FiatPastaFqUint1
	var x51 uint64
	var x52 FiatPastaFqUint1
	var x53 uint64
	var x54 FiatPastaFqUint1
	var x55 uint64
	var x56 FiatPastaFqUint1
	var x57 uint64
	var x58 FiatPastaFqUint1
	var x59, x60, x61, x62, x63, x64, x65, x66, x67 uint64
	var x68 FiatPastaFqUint1
	var x69 uint64
	var x70 FiatPastaFqUint1
	var x71 uint64
	var x72 FiatPastaFqUint1
	var x73 uint64
	var x74 FiatPastaFqUint1
	var x75 uint64
	var x76 FiatPastaFqUint1
	var x77, x78, x79, x80, x81, x82, x83, x84, x85 uint64
	var x86 FiatPastaFqUint1
	var x87 uint64
	var x88 FiatPastaFqUint1
	var x89 uint64
	var x90 FiatPastaFqUint1
	var x91 uint64
	var x92 FiatPastaFqUint1
	var x93 uint64
	var x94 FiatPastaFqUint1
	var x95 uint64
	var x96 FiatPastaFqUint1
	var x97 uint64
	var x98 FiatPastaFqUint1
	var x99, x100, x101, x102, x103, x104, x105, x106, x107 uint64
	var x108 FiatPastaFqUint1
	var x109 uint64
	var x110 FiatPastaFqUint1
	var x111 uint64
	var x112 FiatPastaFqUint1
	var x113 uint64
	var x114 FiatPastaFqUint1
	var x115 uint64
	var x116 FiatPastaFqUint1
	var x117, x118, x119, x120, x121, x122, x123, x124, x125 uint64
	var x126 FiatPastaFqUint1
	var x127 uint64
	var x128 FiatPastaFqUint1
	var x129 uint64
	var x130 FiatPastaFqUint1
	var x131 uint64
	var x132 FiatPastaFqUint1
	var x133 uint64
	var x134 FiatPastaFqUint1
	var x135 uint64
	var x136 FiatPastaFqUint1
	var x137 uint64
	var x138 FiatPastaFqUint1
	var x139, x140, x141, x142, x143, x144, x145, x146, x147 uint64
	var x148 FiatPastaFqUint1
	var x149 uint64
	var x150 FiatPastaFqUint1
	var x151 uint64
	var x152 FiatPastaFqUint1
	var x153 uint64
	var x154 FiatPastaFqUint1
	var x155 uint64
	var x156 FiatPastaFqUint1
	var x157, x158 uint64
	var x159 FiatPastaFqUint1
	var x160 uint64
	var x161 FiatPastaFqUint1
	var x162 uint64
	var x163 FiatPastaFqUint1
	var x164 uint64
	var x165 FiatPastaFqUint1
	var x166 uint64
	var x167 FiatPastaFqUint1
	var x168, x169, x170, x171 uint64

	x1 = arg1[1]
	x2 = arg1[2]
	x3 = arg1[3]
	x4 = arg1[0]

	FiatPastaFqMulXU64(&x5, &x6, x4, uint64(0x96d41af7ccfdaa9))
	FiatPastaFqMulXU64(&x7, &x8, x4, uint64(0x7fae231004ccf590))
	FiatPastaFqMulXU64(&x9, &x10, x4, uint64(0x67bb433d891a16e3))
	FiatPastaFqMulXU64(&x11, &x12, x4, uint64(0xfc9678ff0000000f))
	FiatPastaFqAddCarryXU64(&x13, &x14, 0x0, x12, x9)
	FiatPastaFqAddCarryXU64(&x15, &x16, x14, x10, x7)
	FiatPastaFqAddCarryXU64(&x17, &x18, x16, x8, x5)
	FiatPastaFqMulXU64(&x19, &x20, x11, uint64(0x8c46eb20ffffffff))
	FiatPastaFqMulXU64(&x21, &x22, x19, uint64(0x4000000000000000))
	FiatPastaFqMulXU64(&x23, &x24, x19, uint64(0x224698fc0994a8dd))
	FiatPastaFqMulXU64(&x25, &x26, x19, uint64(0x8c46eb2100000001))
	FiatPastaFqAddCarryXU64(&x27, &x28, 0x0, x26, x23)
	FiatPastaFqAddCarryXU64(&x29, &x30, 0x0, x11, x25)
	FiatPastaFqAddCarryXU64(&x31, &x32, x30, x13, x27)
	FiatPastaFqAddCarryXU64(&x33, &x34, x32, x15, uint64(x28)+x24)
	FiatPastaFqAddCarryXU64(&x35, &x36, x34, x17, x21)
	FiatPastaFqMulXU64(&x37, &x38, x1, uint64(0x96d41af7ccfdaa9))
	FiatPastaFqMulXU64(&x39, &x40, x1, uint64(0x7fae231004ccf590))
	FiatPastaFqMulXU64(&x41, &x42, x1, uint64(0x67bb433d891a16e3))
	FiatPastaFqMulXU64(&x43, &x44, x1, uint64(0xfc9678ff0000000f))
	FiatPastaFqAddCarryXU64(&x45, &x46, 0x0, x44, x41)
	FiatPastaFqAddCarryXU64(&x47, &x48, x46, x42, x39)
	FiatPastaFqAddCarryXU64(&x49, &x50, x48, x40, x37)
	FiatPastaFqAddCarryXU64(&x51, &x52, 0x0, x31, x43)
	FiatPastaFqAddCarryXU64(&x53, &x54, x52, x33, x45)
	FiatPastaFqAddCarryXU64(&x55, &x56, x54, x35, x47)
	FiatPastaFqAddCarryXU64(&x57, &x58, x56, (uint64(x36)+(uint64(x18)+x6))+x22, x49)
	FiatPastaFqMulXU64(&x59, &x60, x51, uint64(0x8c46eb20ffffffff))
	FiatPastaFqMulXU64(&x61, &x62, x59, uint64(0x4000000000000000))
	FiatPastaFqMulXU64(&x63, &x64, x59, uint64(0x224698fc0994a8dd))
	FiatPastaFqMulXU64(&x65, &x66, x59, uint64(0x8c46eb2100000001))
	FiatPastaFqAddCarryXU64(&x67, &x68, 0x0, x66, x63)
	FiatPastaFqAddCarryXU64(&x69, &x70, 0x0, x51, x65)
	FiatPastaFqAddCarryXU64(&x71, &x72, x70, x53, x67)
	FiatPastaFqAddCarryXU64(&x73, &x74, x72, x55, uint64(x68)+x64)
	FiatPastaFqAddCarryXU64(&x75, &x76, x74, x57, x61)
	FiatPastaFqMulXU64(&x77, &x78, x2, uint64(0x96d41af7ccfdaa9))
	FiatPastaFqMulXU64(&x79, &x80, x2, uint64(0x7fae231004ccf590))
	FiatPastaFqMulXU64(&x81, &x82, x2, uint64(0x67bb433d891a16e3))
	FiatPastaFqMulXU64(&x83, &x84, x2, uint64(0xfc9678ff0000000f))
	FiatPastaFqAddCarryXU64(&x85, &x86, 0x0, x84, x81)
	FiatPastaFqAddCarryXU64(&x87, &x88, x86, x82, x79)
	FiatPastaFqAddCarryXU64(&x89, &x90, x88, x80, x77)
	FiatPastaFqAddCarryXU64(&x91, &x92, 0x0, x71, x83)
	FiatPastaFqAddCarryXU64(&x93, &x94, x92, x73, x85)
	FiatPastaFqAddCarryXU64(&x95, &x96, x94, x75, x87)
	FiatPastaFqAddCarryXU64(&x97, &x98, x96, (uint64(x76)+(uint64(x58)+(uint64(x50)+x38)))+x62, x89)
	FiatPastaFqMulXU64(&x99, &x100, x91, uint64(0x8c46eb20ffffffff))
	FiatPastaFqMulXU64(&x101, &x102, x99, uint64(0x4000000000000000))
	FiatPastaFqMulXU64(&x103, &x104, x99, uint64(0x224698fc0994a8dd))
	FiatPastaFqMulXU64(&x105, &x106, x99, uint64(0x8c46eb2100000001))
	FiatPastaFqAddCarryXU64(&x107, &x108, 0x0, x106, x103)
	FiatPastaFqAddCarryXU64(&x109, &x110, 0x0, x91, x105)
	FiatPastaFqAddCarryXU64(&x111, &x112, x110, x93, x107)
	FiatPastaFqAddCarryXU64(&x113, &x114, x112, x95, uint64(x108)+x104)
	FiatPastaFqAddCarryXU64(&x115, &x116, x114, x97, x101)
	FiatPastaFqMulXU64(&x117, &x118, x3, uint64(0x96d41af7ccfdaa9))
	FiatPastaFqMulXU64(&x119, &x120, x3, uint64(0x7fae231004ccf590))
	FiatPastaFqMulXU64(&x121, &x122, x3, uint64(0x67bb433d891a16e3))
	FiatPastaFqMulXU64(&x123, &x124, x3, uint64(0xfc9678ff0000000f))
	FiatPastaFqAddCarryXU64(&x125, &x126, 0x0, x124, x121)
	FiatPastaFqAddCarryXU64(&x127, &x128, x126, x122, x119)
	FiatPastaFqAddCarryXU64(&x129, &x130, x128, x120, x117)
	FiatPastaFqAddCarryXU64(&x131, &x132, 0x0, x111, x123)
	FiatPastaFqAddCarryXU64(&x133, &x134, x132, x113, x125)
	FiatPastaFqAddCarryXU64(&x135, &x136, x134, x115, x127)
	FiatPastaFqAddCarryXU64(&x137, &x138, x136, (uint64(x116)+(uint64(x98)+(uint64(x90)+x78)))+x102, x129)
	FiatPastaFqMulXU64(&x139, &x140, x131, uint64(0x8c46eb20ffffffff))
	FiatPastaFqMulXU64(&x141, &x142, x139, uint64(0x4000000000000000))
	FiatPastaFqMulXU64(&x143, &x144, x139, uint64(0x224698fc0994a8dd))
	FiatPastaFqMulXU64(&x145, &x146, x139, uint64(0x8c46eb2100000001))
	FiatPastaFqAddCarryXU64(&x147, &x148, 0x0, x146, x143)
	FiatPastaFqAddCarryXU64(&x149, &x150, 0x0, x131, x145)
	FiatPastaFqAddCarryXU64(&x151, &x152, x150, x133, x147)
	FiatPastaFqAddCarryXU64(&x153, &x154, x152, x135, uint64(x148)+x144)
	FiatPastaFqAddCarryXU64(&x155, &x156, x154, x137, x141)
	x157 = (uint64(x156) + (uint64(x138) + (uint64(x130) + x118))) + x142
	FiatPastaFqSubBorrowXU64(&x158, &x159, 0x0, x151, uint64(0x8c46eb2100000001))
	FiatPastaFqSubBorrowXU64(&x160, &x161, x159, x153, uint64(0x224698fc0994a8dd))
	FiatPastaFqSubBorrowXU64(&x162, &x163, x161, x155, 0x0)
	FiatPastaFqSubBorrowXU64(&x164, &x165, x163, x157, uint64(0x4000000000000000))
	FiatPastaFqSubBorrowXU64(&x166, &x167, x165, 0x0, 0x0)
	FiatPastaFqCmovznzU64(&x168, x167, x158, x151)
	FiatPastaFqCmovznzU64(&x169, x167, x160, x153)
	FiatPastaFqCmovznzU64(&x170, x167, x162, x155)
	FiatPastaFqCmovznzU64(&x171, x167, x164, x157)
	out1[0] = x168
	out1[1] = x169
	out1[2] = x170
	out1[3] = x171
}

/*
 * The function fiat_pasta_fq_nonzero outputs a single non-zero word if the input is non-zero and zero otherwise.
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
func FiatPastaFqNonZero(out1 *uint64, arg1 [4]uint64) {
	var x1 uint64
	x1 = arg1[0] | (arg1[1] | (arg1[2] | arg1[3]))
	*out1 = x1
}

/*
 * The function fiat_pasta_fq_selectznz is a multi-limb conditional select.
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
func FiatPastaFqSelectZnz(out1 [4]uint64, arg1 FiatPastaFqUint1, arg2, arg3 [4]uint64) {
	var x1, x2, x3, x4 uint64
	FiatPastaFqCmovznzU64(&x1, arg1, arg2[0], arg3[0])
	FiatPastaFqCmovznzU64(&x2, arg1, arg2[1], arg3[1])
	FiatPastaFqCmovznzU64(&x3, arg1, arg2[2], arg3[2])
	FiatPastaFqCmovznzU64(&x4, arg1, arg2[3], arg3[3])

	out1[0] = x1
	out1[1] = x2
	out1[2] = x3
	out1[3] = x4
}

/*
 * The function fiat_pasta_fq_to_bytes serializes a field element NOT in the Montgomery domain to bytes in little-endian order.
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
func FiatPastaFqToBytes(out1 [32]uint8, arg1 [4]uint64) {
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
 * The function fiat_pasta_fq_from_bytes deserializes a field element NOT in the Montgomery domain from bytes in little-endian order.
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
func FiatPastaFqFromBytes(out1 [4]uint64, arg1 [32]uint8) {
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
 * The function fiat_pasta_fq_set_one returns the field element one in the Montgomery domain.
 * Postconditions:
 *   eval (from_montgomery out1) mod m = 1 mod m
 *   0 ≤ eval out1 < m
 *
 * Input Bounds:
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
func FiatPastaFqSetOne(out1 [4]uint64) {
	out1[0] = uint64(0x5b2b3e9cfffffffd)
	out1[1] = uint64(0x992c350be3420567)
	out1[2] = uint64(0xffffffffffffffff)
	out1[3] = uint64(0x3fffffffffffffff)
}

/*
 * The function fiat_pasta_fq_msat returns the saturated represtation of the prime modulus.
 * Postconditions:
 *   twos_complement_eval out1 = m
 *   0 ≤ eval out1 < m
 *
 * Input Bounds:
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
func FiatPastaFqMSat(out1 [5]uint64) {
	out1[0] = uint64(0x8c46eb2100000001)
	out1[1] = uint64(0x224698fc0994a8dd)
	out1[2] = 0x0
	out1[3] = uint64(0x4000000000000000)
	out1[4] = 0x0
}

/*
 * The function fiat_pasta_fq_divstep_precomp returns the precomputed value for Bernstein-Yang-inversion (in montgomery form).
 * Postconditions:
 *   eval (from_montgomery out1) = ⌊(m - 1) / 2⌋^(if (log2 m) + 1 < 46 then ⌊(49 * ((log2 m) + 1) + 80) / 17⌋ else ⌊(49 * ((log2 m) + 1) + 57) / 17⌋)
 *   0 ≤ eval out1 < m
 *
 * Input Bounds:
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
func FiatPastaFqDivStepPreComp(out1 [4]uint64) {
	out1[0] = uint64(0xe6083b32dccd2992)
	out1[1] = uint64(0x624453584f3bdab6)
	out1[2] = uint64(0xba6367a9c5d2c08e)
	out1[3] = uint64(0x1468dbacb19ab3af)
}

/*
 * The function fiat_pasta_fq_divstep computes a divstep.
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
func FiatPastaFqDivStep(out1 *uint64, out2, out3 [5]uint64, out4, out5 [4]uint64, arg1 uint64, arg2, arg3 [5]uint64, arg4, arg5 [4]uint64) {
	var x1 uint64
	var x2, x3 FiatPastaFqUint1
	var x4 uint64
	var x5 FiatPastaFqUint1
	var x6, x7, x8, x9, x10, x11, x12 uint64
	var x13 FiatPastaFqUint1
	var x14 uint64
	var x15 FiatPastaFqUint1
	var x16 uint64
	var x17 FiatPastaFqUint1
	var x18 uint64
	var x19 FiatPastaFqUint1
	var x20 uint64
	var x21 FiatPastaFqUint1
	var x22, x23, x24, x25, x26, x27, x28, x29, x30, x31 uint64
	var x32 FiatPastaFqUint1
	var x33 uint64
	var x34 FiatPastaFqUint1
	var x35 uint64
	var x36 FiatPastaFqUint1
	var x37 uint64
	var x38 FiatPastaFqUint1
	var x39 uint64
	var x40 FiatPastaFqUint1
	var x41 uint64
	var x42 FiatPastaFqUint1
	var x43 uint64
	var x44 FiatPastaFqUint1
	var x45 uint64
	var x46 FiatPastaFqUint1
	var x47 uint64
	var x48 FiatPastaFqUint1
	var x49, x50, x51, x52, x53 uint64
	var x54 FiatPastaFqUint1
	var x55 uint64
	var x56 FiatPastaFqUint1
	var x57 uint64
	var x58 FiatPastaFqUint1
	var x59 uint64
	var x60 FiatPastaFqUint1
	var x61, x62 uint64
	var x63 FiatPastaFqUint1
	var x64 uint64
	var x65 FiatPastaFqUint1
	var x66 uint64
	var x67 FiatPastaFqUint1
	var x68 uint64
	var x69 FiatPastaFqUint1
	var x70, x71, x72, x73 uint64
	var x74 FiatPastaFqUint1
	var x75, x76, x77, x78, x79, x80 uint64
	var x81 FiatPastaFqUint1
	var x82 uint64
	var x83 FiatPastaFqUint1
	var x84 uint64
	var x85 FiatPastaFqUint1
	var x86 uint64
	var x87 FiatPastaFqUint1
	var x88 uint64
	var x89 FiatPastaFqUint1
	var x90, x91, x92, x93, x94 uint64
	var x95 FiatPastaFqUint1
	var x96 uint64
	var x97 FiatPastaFqUint1
	var x98 uint64
	var x99 FiatPastaFqUint1
	var x100 uint64
	var x101 FiatPastaFqUint1
	var x102 uint64
	var x103 FiatPastaFqUint1
	var x104 uint64
	var x105 FiatPastaFqUint1
	var x106 uint64
	var x107 FiatPastaFqUint1
	var x108 uint64
	var x109 FiatPastaFqUint1
	var x110 uint64
	var x111 FiatPastaFqUint1
	var x112 uint64
	var x113 FiatPastaFqUint1
	var x114, x115, x116, x117, x118, x119, x120, x121, x122, x123, x124, x125, x126 uint64

	FiatPastaFqAddCarryXU64(&x1, &x2, 0x0, ^arg1, 0x1)
	x3 = (FiatPastaFqUint1)((FiatPastaFqUint1)(x1>>63) & (FiatPastaFqUint1)((arg3[0])&0x1))
	FiatPastaFqAddCarryXU64(&x4, &x5, 0x0, ^arg1, 0x1)
	FiatPastaFqCmovznzU64(&x6, x3, arg1, x4)
	FiatPastaFqCmovznzU64(&x7, x3, arg2[0], arg3[0])
	FiatPastaFqCmovznzU64(&x8, x3, arg2[1], arg3[1])
	FiatPastaFqCmovznzU64(&x9, x3, arg2[2], arg3[2])
	FiatPastaFqCmovznzU64(&x10, x3, arg2[3], arg3[3])
	FiatPastaFqCmovznzU64(&x11, x3, arg2[4], arg3[4])
	FiatPastaFqAddCarryXU64(&x12, &x13, 0x0, 0x1, ^(arg2[0]))
	FiatPastaFqAddCarryXU64(&x14, &x15, x13, 0x0, ^(arg2[1]))
	FiatPastaFqAddCarryXU64(&x16, &x17, x15, 0x0, ^(arg2[2]))
	FiatPastaFqAddCarryXU64(&x18, &x19, x17, 0x0, ^(arg2[3]))
	FiatPastaFqAddCarryXU64(&x20, &x21, x19, 0x0, ^(arg2[4]))
	FiatPastaFqCmovznzU64(&x22, x3, arg3[0], x12)
	FiatPastaFqCmovznzU64(&x23, x3, arg3[1], x14)
	FiatPastaFqCmovznzU64(&x24, x3, arg3[2], x16)
	FiatPastaFqCmovznzU64(&x25, x3, arg3[3], x18)
	FiatPastaFqCmovznzU64(&x26, x3, arg3[4], x20)
	FiatPastaFqCmovznzU64(&x27, x3, arg4[0], arg5[0])
	FiatPastaFqCmovznzU64(&x28, x3, arg4[1], arg5[1])
	FiatPastaFqCmovznzU64(&x29, x3, arg4[2], arg5[2])
	FiatPastaFqCmovznzU64(&x30, x3, arg4[3], arg5[3])
	FiatPastaFqAddCarryXU64(&x31, &x32, 0x0, x27, x27)
	FiatPastaFqAddCarryXU64(&x33, &x34, x32, x28, x28)
	FiatPastaFqAddCarryXU64(&x35, &x36, x34, x29, x29)
	FiatPastaFqAddCarryXU64(&x37, &x38, x36, x30, x30)
	FiatPastaFqSubBorrowXU64(&x39, &x40, 0x0, x31, uint64(0x8c46eb2100000001))
	FiatPastaFqSubBorrowXU64(&x41, &x42, x40, x33, uint64(0x224698fc0994a8dd))
	FiatPastaFqSubBorrowXU64(&x43, &x44, x42, x35, 0x0)
	FiatPastaFqSubBorrowXU64(&x45, &x46, x44, x37, uint64(0x4000000000000000))
	FiatPastaFqSubBorrowXU64(&x47, &x48, x46, uint64(x38), 0x0)
	x49 = arg4[3]
	x50 = arg4[2]
	x51 = arg4[1]
	x52 = arg4[0]
	FiatPastaFqSubBorrowXU64(&x53, &x54, 0x0, 0x0, x52)
	FiatPastaFqSubBorrowXU64(&x55, &x56, x54, 0x0, x51)
	FiatPastaFqSubBorrowXU64(&x57, &x58, x56, 0x0, x50)
	FiatPastaFqSubBorrowXU64(&x59, &x60, x58, 0x0, x49)
	FiatPastaFqCmovznzU64(&x61, x60, 0x0, uint64(0xffffffffffffffff))
	FiatPastaFqAddCarryXU64(&x62, &x63, 0x0, x53, x61&uint64(0x8c46eb2100000001))
	FiatPastaFqAddCarryXU64(&x64, &x65, x63, x55, x61&uint64(0x224698fc0994a8dd))
	FiatPastaFqAddCarryXU64(&x66, &x67, x65, x57, 0x0)
	FiatPastaFqAddCarryXU64(&x68, &x69, x67, x59, x61&uint64(0x4000000000000000))
	FiatPastaFqCmovznzU64(&x70, x3, arg5[0], x62)
	FiatPastaFqCmovznzU64(&x71, x3, arg5[1], x64)
	FiatPastaFqCmovznzU64(&x72, x3, arg5[2], x66)
	FiatPastaFqCmovznzU64(&x73, x3, arg5[3], x68)
	x74 = (FiatPastaFqUint1)(x22 & 0x1)
	FiatPastaFqCmovznzU64(&x75, x74, 0x0, x7)
	FiatPastaFqCmovznzU64(&x76, x74, 0x0, x8)
	FiatPastaFqCmovznzU64(&x77, x74, 0x0, x9)
	FiatPastaFqCmovznzU64(&x78, x74, 0x0, x10)
	FiatPastaFqCmovznzU64(&x79, x74, 0x0, x11)
	FiatPastaFqAddCarryXU64(&x80, &x81, 0x0, x22, x75)
	FiatPastaFqAddCarryXU64(&x82, &x83, x81, x23, x76)
	FiatPastaFqAddCarryXU64(&x84, &x85, x83, x24, x77)
	FiatPastaFqAddCarryXU64(&x86, &x87, x85, x25, x78)
	FiatPastaFqAddCarryXU64(&x88, &x89, x87, x26, x79)
	FiatPastaFqCmovznzU64(&x90, x74, 0x0, x27)
	FiatPastaFqCmovznzU64(&x91, x74, 0x0, x28)
	FiatPastaFqCmovznzU64(&x92, x74, 0x0, x29)
	FiatPastaFqCmovznzU64(&x93, x74, 0x0, x30)
	FiatPastaFqAddCarryXU64(&x94, &x95, 0x0, x70, x90)
	FiatPastaFqAddCarryXU64(&x96, &x97, x95, x71, x91)
	FiatPastaFqAddCarryXU64(&x98, &x99, x97, x72, x92)
	FiatPastaFqAddCarryXU64(&x100, &x101, x99, x73, x93)
	FiatPastaFqSubBorrowXU64(&x102, &x103, 0x0, x94, uint64(0x8c46eb2100000001))
	FiatPastaFqSubBorrowXU64(&x104, &x105, x103, x96, uint64(0x224698fc0994a8dd))
	FiatPastaFqSubBorrowXU64(&x106, &x107, x105, x98, 0x0)
	FiatPastaFqSubBorrowXU64(&x108, &x109, x107, x100, uint64(0x4000000000000000))
	FiatPastaFqSubBorrowXU64(&x110, &x111, x109, uint64(x101), 0x0)
	FiatPastaFqAddCarryXU64(&x112, &x113, 0x0, x6, 0x1)
	x114 = (x80 >> 1) | ((x82 << 63) & uint64(0xffffffffffffffff))
	x115 = (x82 >> 1) | ((x84 << 63) & uint64(0xffffffffffffffff))
	x116 = (x84 >> 1) | ((x86 << 63) & uint64(0xffffffffffffffff))
	x117 = (x86 >> 1) | ((x88 << 63) & uint64(0xffffffffffffffff))
	x118 = (x88 & uint64(0x8000000000000000)) | (x88 >> 1)
	FiatPastaFqCmovznzU64(&x119, x48, x39, x31)
	FiatPastaFqCmovznzU64(&x120, x48, x41, x33)
	FiatPastaFqCmovznzU64(&x121, x48, x43, x35)
	FiatPastaFqCmovznzU64(&x122, x48, x45, x37)
	FiatPastaFqCmovznzU64(&x123, x111, x102, x94)
	FiatPastaFqCmovznzU64(&x124, x111, x104, x96)
	FiatPastaFqCmovznzU64(&x125, x111, x106, x98)
	FiatPastaFqCmovznzU64(&x126, x111, x108, x100)
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

func FiatPastaFqEquals(x, y [4]uint64) bool {
	var x_minus_y [4]uint64
	FiatPastaFqSub(&x_minus_y, x, y)

	var x_minus_y_nonzero uint64
	FiatPastaFqNonZero(&x_minus_y_nonzero, x_minus_y)
	if x_minus_y_nonzero == 0 {
		return true
	}
	return false
}

func FiatPastaFqCopy(out *[4]uint64, value [4]uint64) {
	for j := 0; j < 4; j++ {
		out[j] = value[j]
	}
}
