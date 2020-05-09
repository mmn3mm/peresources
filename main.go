package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   uint32
}
type OptionalHeader32 struct {
	Magic                   uint16
	MajorLinkerVersion      uint8
	MinorLinkerVersion      uint8
	SizeOfCode              uint32
	SizeOfInitializedData   uint32
	SizeOfUninitializedData uint32
	AddressOfEntryPoint     uint32
	BaseOfCode              uint32
	BaseOfData              uint32
	ImageBase               uint32
	SectionAlignment        uint32
	FileAlignment           uint32
	MajorOSVersion          uint16
	MinorOSVersion          uint16
	MajorImageVersion       uint16
	MinorImageVersion       uint16
	MajorSubsystemVersion   uint16
	MinorSubsystemVersion   uint16
	Win32Version            uint32
	SizeOfImage             uint32
	SizeOfHeaders           uint32
	Checksum                uint32
	Sybsystem               uint16
	DllCharacteristics      uint16
	SizeOfStackReserve      uint32
	SizeOfStackCommit       uint32
	SizeOfHeapReserve       uint32
	SizeOfHeapCommit        uint32
	LoaderFlags             uint32
	NumberOfRvaAndSizes     uint32
	DataDirectories         [16]DataDirectory
}
type CoffHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDataStamp        uint32
	PointerSymbolTable   uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}
type DataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}
type ResourceDirectoryRAW struct {
	Characteristics      uint32
	TimeDateStamp        uint32
	MajorVersion         uint16
	MinorVersion         uint16
	NumberOfNamedEntries uint16
	NumberOfIdEntries    uint16
}
type ResourceDirectory struct {
	depth                uint32
	Characteristics      uint32
	TimeDateStamp        uint32
	MajorVersion         uint16
	MinorVersion         uint16
	NumberOfNamedEntries uint16
	NumberOfIdEntries    uint16
	ResType              string
	Entries              []ResourceDirectoryEntry
}
type ResourceDirectoryEntryPESTRUCTURE struct {
	NameOffset   uint32
	OffsetToData uint32
}
type ResourceDirectoryEntry struct {
	NameOffset            uint32
	OffsetToData          uint32
	Name                  string
	ID                    uint32
	ResourceDirectoryNode ResourceDirectory
	ResourceDataEntryNode ResourceDataEntry
}
type SectionHeader struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	Size                 uint32
	Offset               uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}
type ResourceDataEntry struct {
	OffsetToData uint32
	Size         uint32
	CodePage     uint32
	Reserved     uint32
}

var sections []*SectionHeader

func WideStringToString(wideString []byte, size int) string {
	ret := make([]byte, 0, 0)
	for i := 0; i < size; i += 2 {
		b := wideString[i : i+2]

		if b[0] == 0x00 && b[1] == 0x00 {
			break
		}

		switch b[0] {
		case 0x09:
			ret = append(ret, 0x5c)
			ret = append(ret, 0x5c)
			ret = append(ret, 0x74)
		case 0x0a:
			ret = append(ret, 0x5c)
			ret = append(ret, 0x5c)
			ret = append(ret, 0x6e)
		case 0x0b:
			ret = append(ret, 0x5c)
			ret = append(ret, 0x5c)
			ret = append(ret, 0x76)
		case 0x0c:
			ret = append(ret, 0x5c)
			ret = append(ret, 0x5c)
			ret = append(ret, 0x66)
		case 0x0d:
			ret = append(ret, 0x5c)
			ret = append(ret, 0x5c)
			ret = append(ret, 0x72)
		default:
			ret = append(ret, b[0])
		}
	}

	return string(ret)
}
func readDirectoryRecursively(rootRva uint32, currentDirectoryRva uint32, depth uint32,r *bytes.Reader) (ResourceDirectory, error) {
	var ret ResourceDirectory
	rdRaw := ResourceDirectoryRAW{}
	if _, err := r.Seek(int64(currentDirectoryRva), io.SeekStart); err != nil {
		return ResourceDirectory{}, err
	}
	if err := binary.Read(r, binary.LittleEndian, &rdRaw); err != nil {
		return ResourceDirectory{}, err
	}
	numberOfEntries := rdRaw.NumberOfIdEntries + rdRaw.NumberOfNamedEntries
	currentEntry, _ := r.Seek(0, io.SeekCurrent)
	for i := uint16(0); i < numberOfEntries; i++ {
		var resourceDirectoryEntry ResourceDirectoryEntry
		rdeRaw := ResourceDirectoryEntryPESTRUCTURE{}
		//In case of seeking to name, we have to seek back.
		if _, err := r.Seek(currentEntry, io.SeekStart); err != nil {
			return ResourceDirectory{}, err
		}
		if err := binary.Read(r, binary.LittleEndian, &rdeRaw); err != nil {
			return ResourceDirectory{}, err
		}
		currentEntry, _ = r.Seek(0, io.SeekCurrent)
		isID := rdeRaw.NameOffset&(0x80000000) == 0
		id := rdeRaw.NameOffset &^ (0x80000000)
		if !isID {

			if _, err := r.Seek(int64(id+(rootRva)), io.SeekStart); err != nil {
				return ResourceDirectory{}, err
			}
			//No need for the structure ResourceDirStringU
			var length uint16
			if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
				return ResourceDirectory{}, err
			}
			wideString := make([]byte, length*2)
			r.Read(wideString)
			resourceDirectoryEntry.Name = WideStringToString(wideString, int(length*2))
		} else {
			resourceDirectoryEntry.ID = id & 0xffff
		}
		isDirectory := rdeRaw.OffsetToData&(0x80000000) > 0
		address := rdeRaw.OffsetToData &^ (0x80000000)
		if isDirectory {
			temp, err := readDirectoryRecursively(rootRva, rootRva+address, depth+1,r)
			if err != nil {
				return ResourceDirectory{}, err
			}
			resourceDirectoryEntry.ResourceDirectoryNode = temp
		} else {

			if _, err := r.Seek(int64(address+(rootRva)), io.SeekStart); err != nil {
				return ResourceDirectory{}, err
			}
			resourceDataEntry := ResourceDataEntry{}
			if err := binary.Read(r, binary.LittleEndian, &resourceDataEntry); err != nil {
				return ResourceDirectory{}, err
			}
			resourceDirectoryEntry.ResourceDataEntryNode = resourceDataEntry
		}
		resourceDirectoryEntry.NameOffset = rdeRaw.NameOffset
		resourceDirectoryEntry.OffsetToData = rdeRaw.OffsetToData
		ret.Entries = append(ret.Entries, resourceDirectoryEntry)
	}
	ret.NumberOfIdEntries = rdRaw.NumberOfIdEntries
	ret.NumberOfNamedEntries = rdRaw.NumberOfNamedEntries
	ret.Characteristics = rdRaw.Characteristics
	ret.MajorVersion = rdRaw.MajorVersion
	ret.MinorVersion = rdRaw.MinorVersion
	ret.TimeDateStamp = rdRaw.TimeDateStamp
	ret.depth = depth
	return ret, nil
}
func readResources(resourcesRVA uint32,r *bytes.Reader) *ResourceDirectory {
	if resourcesRVA==0{
		return nil
	}
	rawOffset:=getRawOffset(resourcesRVA)
	if rawOffset==-1{
		fmt.Errorf("something is wrong with currentDirectoryRva")
		return nil
	}
	resourcesRVA=uint32(rawOffset)
	resourceDirectoryRoot, err:= readDirectoryRecursively(resourcesRVA, resourcesRVA, 0,r)
	if err!=nil{
		fmt.Errorf("failed with error:%v",err)
		return nil
	}
	return  &resourceDirectoryRoot

}





func readSectionHeaders(numberofSections uint32,r *bytes.Reader,sectionsStart int64)[]*SectionHeader{
	sectionHeaders := make([]*SectionHeader, numberofSections)

	// loop over each section and populate struct
	for i := 0; i < int(numberofSections); i++ {
		if _, err := r.Seek(sectionsStart+int64(binary.Size(SectionHeader{})*i), io.SeekStart); err != nil {
			return nil
		}
		temp := SectionHeader{}
		if err:= binary.Read(r, binary.LittleEndian, &temp); err != nil {
			return nil
		}
		sectionHeaders[i] = &temp
	}
	return sectionHeaders
}

func getRawOffset(rva uint32)int32{
	for _,sectionHeader:=range sections{
		if rva >= sectionHeader.VirtualAddress && rva<sectionHeader.VirtualAddress+sectionHeader.VirtualSize{
			rva-=sectionHeader.VirtualAddress
			return int32(rva +sectionHeader.Offset)
		}
	}
	return -1
}

func getResourceType(resourceType uint32) string {
	values := []string{"CURSOR", "BITMAP", "ICON", "MENU", "DIALOG", "STRING", "FONTDIR", "FONT", "ACCELERATOR", "RCDATA", "MESSAGETABLE", "GROUP_CURSOR", "UNDOCUMENTED", "GROUP_ICON", "UNDOCUMENTED", "VERSION", "DLGINCLUDE", "UNDOCUMENTED", "PLUGPLAY", "VXD", "ANICURSOR", "ANIICON", "HTML", "MANIFEST"}
	if int(resourceType) > len(values) {
		return "UNDOCUMENTED"
	}
	return values[resourceType-1]
}

func printLanguages(directory ResourceDirectory) {
	for j, entry :=range directory.Entries{
		if entry.Name!=""{
			fmt.Printf("\t\t(%d)Language:%s\n",j, entry.Name)
		}else{
			primaryLanguage:=entry.ID&0xff
			subLanguage:=(entry.ID&0xff00)>>8
			fmt.Printf("\t\t(%d)lang id: 0x%x (Primary Language ID:0x%x| SubLanguage ID:0x%x)\n ",j,entry.ID, primaryLanguage,subLanguage)
		}
	}
}
func printActual(directory ResourceDirectory){
	for j, entry :=range directory.Entries{
		if entry.Name!=""{
			fmt.Printf("\t(%d)Name:%s\n",j, entry.Name)
		}else{
			fmt.Printf("\t(%d)ID:0x%x\n",j, entry.ID)
		}
		printLanguages(entry.ResourceDirectoryNode)
	}
}

func printResources(directory ResourceDirectory){
	for i,entry:=range directory.Entries{
		resourceType:=getResourceType(entry.ID)
		if entry.Name!=""{
			resourceType=entry.Name
		}
		fmt.Printf("(%d)Type:%s\n",i,resourceType)
		printActual(entry.ResourceDirectoryNode)
	}
}

func main() {
	if len(os.Args)!=2{
		fmt.Printf("Usage %s exefile\n",os.Args[0])
		return
	}
	path :=os.Args[1]
	file, err := os.Open(path)
	if err != nil {
		fmt.Errorf("error opening %s file: %v", path, err)
	}
	size, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		fmt.Errorf("error getting size of file %s: %v", path, err)
	}
	file.Seek(0, 0)
	raw := make([]byte, size)
	file.Read(raw)
	r := bytes.NewReader(raw)
	dosHeader := &IMAGE_DOS_HEADER{}
	if err = binary.Read(r, binary.LittleEndian, dosHeader); err != nil {
		fmt.Errorf("error reading dosHeader from file %s: %v", path, err)
	}

	if _, err = r.Seek(int64(dosHeader.E_lfanew)+4, io.SeekStart); err != nil {
		fmt.Errorf("Error seeking to coffHeader in file %s: %v", path, err)
	}

	coffHeader:=&CoffHeader{}
	if err = binary.Read(r, binary.LittleEndian, coffHeader); err != nil {
		fmt.Errorf("Error reading coffHeader in file %s: %v", path, err)
	}


	if _, err = r.Seek(int64(dosHeader.E_lfanew)+4+20, io.SeekStart); err != nil {
		fmt.Errorf("error seeking to optionalHeader in file %s: %v", path, err)
	}

	optionalHeader:=&OptionalHeader32{}
	if err = binary.Read(r, binary.LittleEndian, optionalHeader); err != nil {
		fmt.Errorf("error reading optionalHeader from file %s: %v", path, err)
	}


	resourceDataDirectory:=optionalHeader.DataDirectories[2]
	resourcesRootRVA:=resourceDataDirectory.VirtualAddress
	if resourcesRootRVA==0{
		fmt.Printf("%s has no resources\n",path)
	}
	fmt.Printf("Resources Root RVA:%x\n",resourcesRootRVA)

	sectionsStart := int64(dosHeader.E_lfanew) + 4 + int64(binary.Size(CoffHeader{})) + int64(binary.Size(OptionalHeader32{}))

	sections=readSectionHeaders(uint32(coffHeader.NumberOfSections),r,sectionsStart)

	resourcesRoot:=readResources(resourcesRootRVA,r)
	printResources(*resourcesRoot)
}
