package core

import (
	"github.com/Ihce/sidog/internal/disasm"
	"github.com/Ihce/sidog/internal/strategy"
)

// Run is the single entry-point used by CLI and Python bindings.
func Run(blob []byte, arch string, mode int) ([]disasm.Insn, error) {
	backends, err := disasm.AllCapstone(arch)
	if err != nil {
		return nil, err
	}
	strat := strategy.Select(mode)
	return strat.Disassemble(blob, 0, backends)
}

