// Cross-check the SDK's RFC 6962 Merkle output against transparency-dev/merkle.
// Reads {"max": N} from argv[1]-less defaults; prints JSON lines of roots and
// proofs for leaves sha256(str(i)), i < n, for n = 1..N.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
)

type row struct {
	N           int                 `json:"n"`
	Root        string              `json:"root"`
	Inclusion   map[string][]string `json:"inclusion"`
	Consistency map[string][]string `json:"consistency"`
}

func hx(bs [][]byte) []string {
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = hex.EncodeToString(b)
	}
	return out
}

func main() {
	max := 64
	if len(os.Args) > 1 {
		max, _ = strconv.Atoi(os.Args[1])
	}
	h := rfc6962.DefaultHasher
	enc := json.NewEncoder(os.Stdout)
	for n := 1; n <= max; n++ {
		t := testonly.New(h)
		leaves := make([][]byte, n)
		for i := 0; i < n; i++ {
			d := sha256.Sum256([]byte(strconv.Itoa(i)))
			leaves[i] = d[:]
			t.AppendData(leaves[i])
		}
		root := t.Hash()
		r := row{N: n, Root: hex.EncodeToString(root), Inclusion: map[string][]string{}, Consistency: map[string][]string{}}
		for i := 0; i < n; i++ {
			p, err := t.InclusionProof(uint64(i), uint64(n))
			if err != nil {
				panic(err)
			}
			if err := proof.VerifyInclusion(h, uint64(i), uint64(n), h.HashLeaf(leaves[i]), p, root); err != nil {
				panic(fmt.Sprintf("self-verify inclusion n=%d i=%d: %v", n, i, err))
			}
			r.Inclusion[strconv.Itoa(i)] = hx(p)
		}
		for m := 1; m < n; m++ {
			p, err := t.ConsistencyProof(uint64(m), uint64(n))
			if err != nil {
				panic(err)
			}
			r.Consistency[strconv.Itoa(m)] = hx(p)
		}
		enc.Encode(r)
	}
}
