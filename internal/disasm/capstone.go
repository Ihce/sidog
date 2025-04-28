package disasm

import "github.com/knightsc/gapstone"

// Backend is satisfied by any architecture decoder (Capstone, x/arch, …).
type Backend interface {
	ArchName() string
	Decode(code []byte, base uint64) (Insn, error)
}

/* ---------------- Capstone wrapper ---------------- */

type csBackend struct {
	eng  gapstone.Engine
	name string
}

func newCS(arch gapstone.Arch, mode gapstone.Mode, name string) (Backend, error) {
	eng, err := gapstone.New(arch, mode)
	if err != nil {
		return nil, err
	}
	return &csBackend{eng: eng, name: name}, nil
}

func (c *csBackend) ArchName() string { return c.name }

func (c *csBackend) Decode(b []byte, addr uint64) (Insn, error) {
	ins, err := c.eng.Disasm(b, addr, 1)
	if err != nil || len(ins) == 0 {
		return Insn{}, err
	}
	i := ins[0]
	return Insn{
		ISA:      c.name,
		Offset:   addr,
		Size:     uint32(i.Size),
		Mnemonic: i.Mnemonic,
		Operands: i.OpStr,
	}, nil
}

/* ------------- helper to load Capstone back-ends ------------------ */

func AllCapstone(filter string) ([]Backend, error) {
	var out []Backend
	add := func(b Backend, e error) {
		if e == nil {
			out = append(out, b)
		}
	}

	if filter == "" || filter == "x86" {
		add(newCS(gapstone.CS_ARCH_X86, gapstone.CS_MODE_64, "x86"))
	}
	if filter == "" || filter == "thumb" {
		add(newCS(gapstone.CS_ARCH_ARM, gapstone.CS_MODE_THUMB, "thumb"))
	}
	if filter == "" || filter == "arm" {
		add(newCS(gapstone.CS_ARCH_ARM, gapstone.CS_MODE_ARM, "arm"))
	}
	if filter == "" || filter == "aarch64" {
		add(newCS(gapstone.CS_ARCH_ARM64, gapstone.CS_MODE_ARM, "aarch64"))
	}
	return out, nil
}
