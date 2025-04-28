package disasm

// Insn is the common instruction record shared by all strategies.
type Insn struct {
	ISA      string `json:"isa"`
	Offset   uint64 `json:"offset"`
	Size     uint32 `json:"size"`
	Mnemonic string `json:"mnemonic"`
	Operands string `json:"operands"`
}
