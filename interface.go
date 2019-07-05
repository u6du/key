package key

type BytePrivate struct {
	Byte []byte
}

type BytePublic struct {
	Byte []byte
}

type Private interface {
	Self() *BytePrivate
	Public() Public
}

type Public interface {
	Self() *BytePublic
}

func (p *BytePrivate) Self() *BytePrivate {
	return p
}

func (p *BytePublic) Self() *BytePublic {
	return p
}
