package pasta

import "encoding/json"

type MinaMessage struct {
	Transaction []Field  `json:"transaction"`
	SpongeIV    [3]Field `json:"spongeIV"`
}

func (mm MinaMessage) ToBytes() []byte {
	bytes, err := json.Marshal(mm)
	if err != nil {
		return nil
	}
	return bytes
}

func NewMinaMessage(input []byte) (*MinaMessage, error) {
	var minaMessage = MinaMessage{}
	err := json.Unmarshal(input, &minaMessage)
	if err != nil {
		return nil, err
	}
	return &minaMessage, nil
}

func MessageHash(pub []byte, r_mont [4]uint64, message MinaMessage) []byte {
	var pubAffine Affine
	pubAffine.FromBigEndianBytes(pub)
	message.Transaction = append(message.Transaction, pubAffine.X, pubAffine.Y, r_mont)

	ctx := Poseidon3WInit(message.SpongeIV[:])
	PoseidonUpdate(&ctx, message.Transaction)
	return PoseidonDigest(&ctx)
}
