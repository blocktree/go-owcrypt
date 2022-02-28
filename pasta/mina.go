package pasta

import "encoding/json"

type MinaMessage struct {
	TransactionPrefix []Field  `json:"transactionPrefix"`
	TransactionSuffix []Field  `json:"transactionSuffix"`
	SpongeIV          [3]Field `json:"spongeIV"`
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
	var transaction []Field
	pubAffine.FromBigEndianBytes(pub)
	transaction = append(transaction, message.TransactionPrefix...)
	transaction = append(transaction, pubAffine.X, pubAffine.Y, r_mont)
	transaction = append(transaction, message.TransactionSuffix...)

	ctx := Poseidon3WInit(message.SpongeIV[:])
	PoseidonUpdate(&ctx, transaction)
	return PoseidonDigest(&ctx)
}
