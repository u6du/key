package key

type BytePrivate struct {
	byte []byte
}

type BytePublic struct {
	byte []byte
}

type Private interface {
	Byte() []byte
	Public() Public
}

type Public interface {
	Byte() []byte
}

func (p *BytePrivate) Byte() []byte {
	return p.byte
}

func (p *BytePublic) Byte() []byte {
	return p.byte
}
