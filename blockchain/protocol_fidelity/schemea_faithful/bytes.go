package schemeafaithful


func (g *Group) ElemSizeBytes() int { return (g.P.BitLen() + 7) / 8 }

func (g *Group) ScalarSizeBytes() int { return (g.ExpMod.BitLen() + 7) / 8 }

func (g *Group) CipherTextBytes(ct *CipherText) int {
	if ct == nil {
		return 0
	}
	return 2 * g.ElemSizeBytes()
}

func (g *Group) ZKProofBytes(pf *ZKProof) int {
	if pf == nil {
		return 0
	}
	return 2*g.ElemSizeBytes() + 2*g.ScalarSizeBytes()
}

func (g *Group) PartialDecryptBytes() int { return g.ElemSizeBytes() }
