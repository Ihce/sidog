package strategy

import "github.com/Ihce/sidog/internal/disasm"

/* ---------------- interface & selector ---------------- */

type Strategy interface {
	Disassemble(blob []byte, base uint64, be []disasm.Backend) ([]disasm.Insn, error)
	Name() string
}

func Select(mode int) Strategy {
	switch mode {
	case 0:
		return &Linear{}
	case 1:
		return &Recursive{}
	case 3:
		return &Probabilistic{Thr: 0.6}
	default:
		return &Superset{}
	}
}

/* ---------------- Linear sweep ----------------------- */

type Linear struct{}

func (Linear) Name() string { return "linear" }

func (Linear) Disassemble(b []byte, base uint64, be []disasm.Backend) ([]disasm.Insn, error) {
	var out []disasm.Insn
	dec := be[0]
	for off := uint64(0); off < uint64(len(b)); {
		ins, err := dec.Decode(b[off:], base+off)
		if err != nil || ins.Size == 0 {
			break
		}
		out = append(out, ins)
		off += uint64(ins.Size)
	}
	return out, nil
}

/* ---------------- Superset scan ---------------------- */

type Superset struct{}

func (Superset) Name() string { return "superset" }

func (Superset) Disassemble(b []byte, base uint64, be []disasm.Backend) ([]disasm.Insn, error) {
	var out []disasm.Insn
	for off := uint64(0); off < uint64(len(b)); off++ {
		for _, dec := range be {
			ins, err := dec.Decode(b[off:], base+off)
			if err == nil && ins.Size > 0 {
				out = append(out, ins)
				break
			}
		}
	}
	return out, nil
}

/* ---------------- Stubs (fill in later) -------------- */

type Recursive struct{}

func (Recursive) Name() string { return "recursive" }

func (Recursive) Disassemble([]byte, uint64, []disasm.Backend) ([]disasm.Insn, error) {
	return nil, nil
}

type Probabilistic struct{ Thr float32 }

func (Probabilistic) Name() string { return "probabilistic" }

func (Probabilistic) Disassemble([]byte, uint64, []disasm.Backend) ([]disasm.Insn, error) {
	return nil, nil
}
