package etw

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/binparsergen/reader"
	"www.velocidex.com/golang/go-pe"
)

type PEExport struct {
	name string
	rva  int64
}

type PESymbols struct {
	exports []PEExport
}

func (self *PESymbols) getFuncName(rva int64) string {
	i := sort.Search(len(self.exports), func(i int) bool {
		return self.exports[i].rva > rva
	}) - 1

	if i >= 0 && i < len(self.exports) {
		return self.exports[i].name
	}
	return ""
}

type Mapping struct {
	Pid, BaseAddr, EndAddr uint64
	Filename               string
	dll                    string
}

func (self *KernelInfoManager) NewMapping(event *ordereddict.Dict) (res *Mapping, err error) {
	res = &Mapping{}

	ImageBase, _ := event.GetString("ImageBase")
	res.BaseAddr, err = strconv.ParseUint(ImageBase, 0, 64)
	if err != nil {
		return nil, err
	}

	ImageSize, _ := event.GetString("ImageSize")
	Size, err := strconv.ParseUint(ImageSize, 0, 64)
	if err != nil {
		return nil, err
	}

	res.EndAddr = res.BaseAddr + Size

	ProcessId, _ := event.GetString("ProcessId")
	res.Pid, err = strconv.ParseUint(ProcessId, 0, 64)
	if err != nil {
		return nil, err
	}

	res.Filename, _ = event.GetString("FileName")
	res.Filename = self.normalizeFilename(res.Filename)
	event.Update("FileName", res.Filename)
	res.dll = filepath.Base(res.Filename)

	return res, nil
}

func (self *KernelInfoManager) openPE(filename string) (*PESymbols, error) {
	res := &PESymbols{}

	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	reader, err := reader.NewPagedReader(fd, 4096, 100)
	if err != nil {
		return nil, err
	}

	pe_file, err := pe.NewPEFile(reader)
	if err != nil {
		return nil, err
	}

	for _, desc := range pe_file.ExportRVAs() {
		res.exports = append(res.exports, PEExport{
			name: desc.Name,
			rva:  desc.RVA,
		})
	}

	// Sort so we can binary search it.
	sort.Slice(res.exports, func(i, j int) bool {
		return res.exports[i].rva < res.exports[j].rva
	})

	return res, nil
}
