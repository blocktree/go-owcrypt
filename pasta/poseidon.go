package pasta

type State [MaxSpongeWidth]Field

type PoseidonCtx struct {
	State       State
	Absorbed    int
	SpongeWidth int
	SpongeRate  int
	FullRounds  int
	SBoxAlpha   uint8
	Type        uint8
	RoundKeys   [][]Field
	MdsMatrix   [][]Field
	PerMutation func(ctx *PoseidonCtx)
}

func MatrixMul(s1 *State, m [][]Field, width int) {
	var tmp Field
	var s2 State

	for row := 0; row < width; row++ {
		for col := 0; col < width; col++ {
			var t0 Field
			FieldMul(&t0, s1[col], m[row][col]) //*(*Field)(m + (row*width+col)*LimbsPerField))
			FieldCopy(&tmp, s2[row])
			FieldAdd(&s2[row], tmp, t0)
		}
	}

	for col := 0; col < width; col++ {
		FieldCopy(&s1[col], s2[col])
	}
}

func PerMutation3W(ctx *PoseidonCtx) {
	var tmp Field
	for r := 0; r < ctx.FullRounds; r++ {
		for i := 0; i < ctx.SpongeWidth; i++ {
			FieldCopy(&tmp, ctx.State[i])
			FieldAdd(&ctx.State[i], tmp, ctx.RoundKeys[r][i])
		}
		for i := 0; i < ctx.SpongeWidth; i++ {
			FieldCopy(&tmp, ctx.State[i])
			FieldPow(&ctx.State[i], tmp, ctx.SBoxAlpha)
		}

		MatrixMul(&ctx.State, ctx.MdsMatrix, ctx.SpongeWidth)
	}
	for i := 0; i < ctx.SpongeWidth; i++ {
		FieldCopy(&tmp, ctx.State[i])
		FieldAdd(&ctx.State[i], tmp, ctx.RoundKeys[ctx.FullRounds][i])
	}
}

func NewPoseidonCtx3W() PoseidonCtx {
	return PoseidonCtx{
		State:       State{},
		Absorbed:    0,
		SpongeWidth: SpongeWidth3W,
		SpongeRate:  SpongeRate3W,
		FullRounds:  RoundCount3W - 1,
		SBoxAlpha:   SBoxAlpha3W,
		Type:        0,
		RoundKeys:   RoundKeys3W,
		MdsMatrix:   MdsMatrix3W,
		PerMutation: PerMutation3W,
	}
}
func Poseidon3WInit(spongeIV []Field) PoseidonCtx {
	ctx := NewPoseidonCtx3W()
	if spongeIV != nil && len(spongeIV) == 3 {
		ctx.State[0].Set(spongeIV[0])
		ctx.State[1].Set(spongeIV[1])
		ctx.State[2].Set(spongeIV[2])
	}

	return ctx
}

func PoseidonUpdate(ctx *PoseidonCtx, input []Field) {
	if input == nil {
		return
	}
	var tmp Field
	for i := 0; i < len(input); i++ {
		if ctx.Absorbed == ctx.SpongeRate {
			ctx.PerMutation(ctx)
			ctx.Absorbed = 0
		}

		FieldCopy(&tmp, ctx.State[ctx.Absorbed])
		FieldAdd(&ctx.State[ctx.Absorbed], tmp, input[i])
		ctx.Absorbed++
	}
}

func PoseidonDigest(ctx *PoseidonCtx) []byte {
	ctx.PerMutation(ctx)
	var tmp [4]uint64
	FiatPastaFpFromMontgomery(&tmp, ctx.State[0])

	digest := U64ArrayToBytesArray(tmp)
	return reverseBytes(digest[:])
}
