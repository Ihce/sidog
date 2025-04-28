package bindgo

/*
#cgo LDFLAGS: -lcapstone
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"unsafe"

	"github.com/Ihce/sidog/internal/core"
)

//export DisassembleBytes
func DisassembleBytes(ptr unsafe.Pointer, n C.int,
	arch *C.char, mode C.int, pout **C.char) C.int {

	blob := C.GoBytes(ptr, n)
	ins, err := core.Run(blob, C.GoString(arch), int(mode))
	if err != nil {
		return -1
	}
	js, _ := json.Marshal(ins)
	*pout = C.CString(string(js))
	return 0
}
