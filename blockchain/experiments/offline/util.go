// util.go holds small helpers shared by the offline measurements.
package offline

import (
	"bytes"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"

	"c5full/internal/c5/m1"
)

func timeNowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

func grothProofOf(p *m1.Prover, raw []byte) groth16.Proof {
	pf := groth16.NewProof(ecc.BLS12_381)
	_, err := pf.ReadFrom(bytes.NewReader(raw))
	if err != nil {
		panic(err)
	}
	return pf
}

type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uint64
	WorkingSetSize             uint64
	QuotaPeakPagedPoolUsage    uint64
	QuotaPagedPoolUsage        uint64
	QuotaPeakNonPagedPoolUsage uint64
	QuotaNonPagedPoolUsage     uint64
	PagefileUsage              uint64
	PeakPagefileUsage          uint64
}

var (
	procGetPMI  = findProc("psapi.dll", "GetProcessMemoryInfo")
	procCurProc = findProc("kernel32.dll", "GetCurrentProcess")
)

func findProc(dllName, procName string) *syscall.Proc {
	d, err := syscall.LoadDLL(dllName)
	if err != nil {
		return nil
	}
	p, err := d.FindProc(procName)
	if err != nil {
		return nil
	}
	return p
}

func peakRSSMBWin() float64 {
	if runtime.GOOS != "windows" {
		return -1
	}
	if v := os.Getenv("V3EXP_RSS_MB"); v != "" {
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			return f
		}
	}
	if procGetPMI == nil || procCurProc == nil {
		return -1
	}
	h, _, _ := procCurProc.Call()
	var pmc processMemoryCounters
	pmc.CB = uint32(unsafe.Sizeof(pmc))
	r1, _, _ := procGetPMI.Call(h, uintptr(unsafe.Pointer(&pmc)), uintptr(unsafe.Sizeof(pmc)))
	if r1 == 0 {
		return -1
	}
	return float64(pmc.PeakWorkingSetSize) / (1024 * 1024)
}
