package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"golang.org/x/sys/windows"
)

type SHELLEXECUTEINFO struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIcon        uintptr
	hProcess     uintptr
}

const (
	PROCESS_ALL_ACCESS            = 0x1F0FFF
	MEM_COMMIT                    = 0x1000
	statusSuccess                 = 0
	securityAnonymousLogonRid     = 0x00000007
	securityLocalSystemRid        = 0x00000012
	securityNtAuthority           = 0x00000005
	securityPackageId             = 0x0000000a
	securityTokenPrimary          = 1
	securityImpersonation         = 2
	securityDelegation            = 3
	securityAnonymous             = 0
	securityIdentification        = 1
	securityImpersonationDisabled = 0
	SE_DEBUG_NAME                 = "SeDebugPrivilege"
	SE_ASSIGNPRIMARYTOKEN_NAME    = "SeAssignPrimaryTokenPrivilege"
	SE_LOAD_DRIVER_NAME           = "SeLoadDriverPrivilege"
	SE_SYSTEM_ENVIRONMENT_NAME    = "SeSystemEnvironmentPrivilege"
	SE_TAKE_OWNERSHIP_NAME        = "SeTakeOwnershipPrivilege"
)

type PROCESS_MEMORY_COUNTERS_EX struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}
type MZHeader struct {
	Signature    uint16
	LastPageSize uint16
	Pages        uint16
	Relocations  uint16
	HeaderSize   uint16
	MinAlloc     uint16
	MaxAlloc     uint16
	InitialSS    uint16
	InitialSP    uint16
	Checksum     uint16
	InitialIP    uint16
	InitialCS    uint16
	RelocAddr    uint16
	OverlayNum   uint16
	Reserved     [8]uint16
	OEMID        uint16
	OEMInfo      uint16
	Reserved2    [20]uint16
	PEHeaderAddr uint32
}

type PEHeader struct {
	Signature            uint32
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type PESectionHeader struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}
type ProcessEntry32 struct {
	dwSize              uint32
	cntUsage            uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [syscall.MAX_PATH]uint16
}
type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUIDAndAttributes struct {
	Luid       LUID
	Attributes uint32
}

var (
	securityLocalSystemSid = []byte{
		1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
		securityNtAuthority, securityLocalSystemRid & 0xFF, securityLocalSystemRid >> 8 & 0xFF, 0, 0, 0, 0,
	}

	securityAnonymousSid = []byte{
		1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
		securityNtAuthority, securityAnonymousLogonRid & 0xFF, securityAnonymousLogonRid >> 8 & 0xFF, 0, 0, 0, 0,
	}
)
var (
	modkernel32                      = windows.NewLazySystemDLL("kernel32.dll")
	modpsapi                         = windows.NewLazySystemDLL("psapi.dll")
	modSecur32                       = syscall.NewLazyDLL("secur32.dll")
	modAdvapi32                      = syscall.NewLazyDLL("advapi32.dll")
	procLsaRegisterLogonProcessW     = modSecur32.NewProc("LsaRegisterLogonProcess")
	procLsaConnectUntrusted          = modSecur32.NewProc("LsaConnectUntrusted")
	procLsaCallAuthenticationPackage = modSecur32.NewProc("LsaCallAuthenticationPackage")
	procLsaFreeReturnBuffer          = modSecur32.NewProc("LsaFreeReturnBuffer")
	procCloseHandle                  = modkernel32.NewProc("CloseHandle")
	procCreateToolhelp32Snapshot     = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First               = modkernel32.NewProc("Process32FirstW")
	procProcess32Next                = modkernel32.NewProc("Process32NextW")
	procOpenProcess                  = modkernel32.NewProc("OpenProcess")
	procReadProcessMemory            = modkernel32.NewProc("ReadProcessMemory")
	procGetProcessMemoryInfo         = modpsapi.NewProc("GetProcessMemoryInfo")
	procVirtualQueryEx               = modkernel32.NewProc("VirtualQueryEx")
)

func createToolhelp32Snapshot() (syscall.Handle, error) {
	ret, _, err := procCreateToolhelp32Snapshot.Call(uintptr(0x2), uintptr(0x0))
	if ret == uintptr(syscall.InvalidHandle) {
		return syscall.InvalidHandle, err
	}
	return syscall.Handle(ret), nil
}
func protectionFlagsToString(protect uint32) string {
	flags := make([]string, 0)

	read := protect&windows.PAGE_READONLY != 0 || protect&windows.PAGE_READWRITE != 0 || protect&windows.PAGE_WRITECOPY != 0 || protect&windows.PAGE_EXECUTE_READ != 0 || protect&windows.PAGE_EXECUTE_READWRITE != 0 || protect&windows.PAGE_EXECUTE_WRITECOPY != 0
	write := protect&windows.PAGE_READWRITE != 0 || protect&windows.PAGE_WRITECOPY != 0 || protect&windows.PAGE_EXECUTE_READWRITE != 0 || protect&windows.PAGE_EXECUTE_WRITECOPY != 0
	execute := protect&windows.PAGE_EXECUTE != 0 || protect&windows.PAGE_EXECUTE_READ != 0 || protect&windows.PAGE_EXECUTE_READWRITE != 0 || protect&windows.PAGE_EXECUTE_WRITECOPY != 0

	if read {
		flags = append(flags, "R")
	}
	if write {
		flags = append(flags, "W")
	}
	if execute {
		flags = append(flags, "X")
	}

	return strings.Join(flags, "")
}
func getProcessList(snapshot syscall.Handle) ([]ProcessEntry32, error) {
	var processes []ProcessEntry32

	var process ProcessEntry32
	process.dwSize = uint32(unsafe.Sizeof(process))

	ret, _, err := procProcess32First.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&process)))
	if ret == 0 {
		return nil, err
	}

	for {
		processes = append(processes, process)

		process = ProcessEntry32{}
		process.dwSize = uint32(unsafe.Sizeof(process))

		ret, _, err := procProcess32Next.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&process)))
		if ret == 0 {
			if errno, ok := err.(syscall.Errno); ok && errno == syscall.ERROR_NO_MORE_FILES {
				break
			}
			return nil, err
		}
	}

	return processes, nil
}
func findPEOffset(data []byte, pos int) int {
	minPeOffset := 0x40
	maxPeOffset := 0x200

	for offset := minPeOffset; offset <= maxPeOffset; offset++ {
		if pos+offset+4 > len(data) {
			break
		}
		if bytes.Equal(data[pos+offset:pos+offset+4], []byte{0x50, 0x45, 0x00, 0x00}) {
			return offset
		}
	}

	return -1
}

func findMZHeaders(buffer []byte) []int {
	dosMagic := []byte("MZ")
	mzPositions := []int{}

	for pos := 0; pos < len(buffer)-len(dosMagic); pos++ {
		if bytes.Equal(buffer[pos:pos+len(dosMagic)], dosMagic) {
			mzPositions = append(mzPositions, pos)
		}
	}

	return mzPositions
}

func extractExecutables(inputPath, outputPath string) {
	data, err := ioutil.ReadFile(inputPath)
	if err != nil {
		log.Fatalf("Failed to read input file: %v", err)
	}
	// Create a new folder based on the dump file name
	dumpFileName := filepath.Base(inputPath)
	dumpFileNameWithoutExt := strings.TrimSuffix(dumpFileName, filepath.Ext(dumpFileName))
	outputPath = filepath.Join(outputPath, dumpFileNameWithoutExt)
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		err := os.Mkdir(outputPath, 0755)
		if err != nil {
			log.Fatalf("Failed to create output directory: %v", err)
		}
	}
	mzOffsets := findMZHeaders(data)

	count := 0
	headers := make(map[string]bool)

	for _, pos := range mzOffsets {
		peHeaderAddr := int(binary.LittleEndian.Uint32(data[pos+0x3C : pos+0x3C+4]))
		peHeaderPos := pos + peHeaderAddr

		if peHeaderAddr <= 0 || peHeaderPos >= len(data) || peHeaderPos+4 > len(data) {
			continue
		}

		if bytes.Equal(data[peHeaderPos:peHeaderPos+4], []byte{0x50, 0x45, 0x00, 0x00}) {
			peMachine := binary.LittleEndian.Uint16(data[peHeaderPos+4 : peHeaderPos+4+2])

			if peMachine == 0x14c || peMachine == 0x8664 {
				peSize := binary.LittleEndian.Uint32(data[peHeaderPos+0x50 : peHeaderPos+0x50+4])
				fileAlignment := binary.LittleEndian.Uint32(data[peHeaderPos+0x3C : peHeaderPos+0x3C+4])

				if peSize != 0 && peHeaderPos+int(peSize) <= len(data) && peSize <= 100000000 {
					headerStr := string(data[peHeaderPos : peHeaderPos+min(1024, int(peSize))])

					if _, found := headers[headerStr]; !found {
						headers[headerStr] = true

						padding := 0
						if int(peSize)%int(fileAlignment) != 0 {
							padding = int(fileAlignment) - int(peSize)%int(fileAlignment)
						}

						extractedSize := int(peSize) + padding
						if peHeaderPos+extractedSize <= len(data) {
							filename := filepath.Join(outputPath, fmt.Sprintf("%s%d.exe", dumpFileNameWithoutExt, count))
							count++

							err = ioutil.WriteFile(filename, data[pos:pos+extractedSize], 0644)
							if err != nil {
								log.Printf("Failed to write output file: %v", err)
							} else {
								fmt.Printf("Extracted file: %s\n", filename)
							}
						}
					}
				}
			}
		}
	}

	if count == 0 {
		fmt.Println("No executables found in input file.")
	} else {
		fmt.Printf("Extracted %d executables to output path: %s\n", count, outputPath)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func enablePrivilege(privilegeName string) error {
	var token windows.Token
	currentProcess, _ := windows.GetCurrentProcess()
	err := windows.OpenProcessToken(currentProcess, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)

	if err != nil {
		return err
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(privilegeName), &luid)
	if err != nil {
		return err
	}

	privileges := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}

	err = windows.AdjustTokenPrivileges(token, false, &privileges, 0, nil, nil)

	if err != nil && err != windows.ERROR_NOT_ALL_ASSIGNED {
		return err
	}

	return nil
}
func runWithPrivileges(targetFunc func()) {
	// Enable the required privileges
	privileges := []string{
		SE_ASSIGNPRIMARYTOKEN_NAME,
		SE_LOAD_DRIVER_NAME,
		SE_SYSTEM_ENVIRONMENT_NAME,
		SE_TAKE_OWNERSHIP_NAME,
		SE_DEBUG_NAME,
	}

	for _, privilege := range privileges {
		err := enablePrivilege(privilege)
		if err != nil {
			log.Fatalf("Failed to enable %s: %v", privilege, err)
		}
	}

	// Run the provided function with the required privileges
	targetFunc()
}
func setMemory(ptr unsafe.Pointer, value byte, size uintptr) {
	bytes := make([]byte, size)
	for i := range bytes {
		bytes[i] = value
	}
	copy((*[1 << 30]byte)(ptr)[:size:size], bytes)
}
func dumpProcessMemory(processID uint32, exeFile [syscall.MAX_PATH]uint16, folderName string) error {
	exePath := syscall.UTF16ToString(exeFile[:])

	hProcess, _, err := procOpenProcess.Call(uintptr(PROCESS_ALL_ACCESS), uintptr(0), uintptr(processID))
	if hProcess == 0 {
		return err
	}
	defer syscall.CloseHandle(syscall.Handle(hProcess))

	outputPath := filepath.Join(folderName, fmt.Sprintf("%s_%d.dmp", exePath, processID))
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	type MemoryRange struct {
		BaseAddress uintptr
		RegionSize  uintptr
		Protect     uint32
	}

	var memoryRanges []MemoryRange

	for baseAddress := uintptr(0); ; {
		baseAddress = (baseAddress + 0xFFFF) & ^uintptr(0xFFFF)
		var memoryBasicInfo MEMORY_BASIC_INFORMATION
		setMemory(unsafe.Pointer(&memoryBasicInfo), 0, unsafe.Sizeof(memoryBasicInfo))

		ret, _, _ := procVirtualQueryEx.Call(hProcess, baseAddress, uintptr(unsafe.Pointer(&memoryBasicInfo)), unsafe.Sizeof(memoryBasicInfo))

		if ret == 0 {
			break
		}

		if memoryBasicInfo.State == MEM_COMMIT {
			buffer := make([]byte, memoryBasicInfo.RegionSize)
			var bytesRead uintptr
			ret, _, err = procReadProcessMemory.Call(hProcess, memoryBasicInfo.BaseAddress, uintptr(unsafe.Pointer(&buffer[0])), uintptr(memoryBasicInfo.RegionSize), uintptr(unsafe.Pointer(&bytesRead)))
			if ret != 0 {
				outputFile.Write(buffer[:bytesRead])
				memoryRanges = append(memoryRanges, MemoryRange{BaseAddress: baseAddress, RegionSize: memoryBasicInfo.RegionSize, Protect: memoryBasicInfo.Protect})
			}
		}

		baseAddress += memoryBasicInfo.RegionSize
	}

	log.Printf("Memory dump for PID %d saved to: %s\n", processID, outputPath)
	log.Printf("Memory ranges for PID %d:\n", processID)
	extractExecutables(outputPath, folderName)
	for _, memRange := range memoryRanges {
		protectionStr := protectionFlagsToString(memRange.Protect)
		log.Printf("Base address: %X, Region size: %X, Protection: %s\n", memRange.BaseAddress, memRange.RegionSize, protectionStr)
	}

	return nil
}
func runAsAdmin(programPath string) error {
	// Load shell32.dll library
	shell32, err := syscall.LoadDLL("shell32.dll")
	if err != nil {
		return err
	}
	defer shell32.Release()

	// Get the pointer to the ShellExecuteEx function
	shellExecuteEx, err := shell32.FindProc("ShellExecuteExW")
	if err != nil {
		return err
	}

	// Prepare parameters for ShellExecuteEx function
	sei := &SHELLEXECUTEINFO{
		cbSize: uint32(unsafe.Sizeof(SHELLEXECUTEINFO{})),
		lpVerb: syscall.StringToUTF16Ptr("runas"),
		lpFile: syscall.StringToUTF16Ptr(programPath),
		nShow:  syscall.SW_NORMAL,
	}

	// Call the ShellExecuteEx function to run the program as administrator
	ret, _, err := shellExecuteEx.Call(uintptr(unsafe.Pointer(sei)))
	if ret == 0 {
		return err
	}

	return nil
}
func runMemoryDumper(folderName string, progressChannel chan float64, statusChannel chan string) (string, error) {
	defer close(progressChannel)
	defer close(statusChannel)
	var output strings.Builder

	logFile, err := os.OpenFile("memory_dumper.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return "", fmt.Errorf("Error creating log file: %v", err)
	}
	defer logFile.Close()

	log.SetOutput(logFile)
	snapshot, err := createToolhelp32Snapshot()
	if err != nil {
		return "", fmt.Errorf("Error creating snapshot: %v", err)
	}
	defer syscall.CloseHandle(snapshot)

	processes, err := getProcessList(snapshot)
	if err != nil {
		return "", fmt.Errorf("Error getting process list: %v", err)
	}

	currentProcessID := syscall.Getpid()

	for index, process := range processes {
		if process.th32ProcessID == 0 {
			continue
		}

		if process.th32ProcessID == uint32(currentProcessID) {
			continue
		}

		processInfo := fmt.Sprintf("Process: %s (PID: %d)\n", syscall.UTF16ToString(process.szExeFile[:]), process.th32ProcessID)
		output.WriteString(processInfo)

		if err := dumpProcessMemory(process.th32ProcessID, process.szExeFile, folderName); err != nil {
			errMsg := fmt.Sprintf("Failed to dump memory: %v\n", err)
			output.WriteString(errMsg)
		} else {
			status := fmt.Sprintf("Successfully dumped memory for process %s (PID: %d)\n", syscall.UTF16ToString(process.szExeFile[:]), process.th32ProcessID)
			statusChannel <- status
		}

		progress := float64(index+1) / float64(len(processes))
		progressChannel <- progress
	}

	return output.String(), nil
}

var mainWindow *walk.MainWindow
var progressLabel *walk.Label
var statusLabel *walk.Label
var outputTextEdit *walk.TextEdit

func updateProgress(progress float64) {
	if mainWindow != nil {
		mainWindow.Synchronize(func() {
			outputTextEdit.AppendText(fmt.Sprintf("Progress: %.2f%%\r\n", progress*100))
		})
	}
}

func updateStatus(status string) {
	if mainWindow != nil {
		mainWindow.Synchronize(func() {
			outputTextEdit.AppendText(status + "\r\n")
		})
	}
}
func start(progressChannel chan<- float64, statusChannel chan string) {

	isAdmin, err := isUserAnAdmin()
	if err != nil {
		statusChannel <- fmt.Sprintf("Error checking if user is an admin: %s", err)
		return
	}

	if !isAdmin {
		// Get the path of the current executable
		programPath, err := os.Executable()
		if err != nil {
			statusChannel <- fmt.Sprintf("Error getting the current executable path: %s", err)
			return
		}

		err = runAsAdmin(programPath)
		if err != nil {
			statusChannel <- fmt.Sprintf("Error running the program as an administrator: %s", err)
			return
		}

		// Exit the current non-admin instance of the program
		return
	}

	// Create an output folder with the current date
	currentDate := time.Now().Format("2006-01-02")
	folderName := fmt.Sprintf("output_%s", currentDate)
	err = os.MkdirAll(folderName, 0755)
	if err != nil {
		statusChannel <- fmt.Sprintf("Error creating output folder: %s", err)
		return
	}

	// Create a buffered progress channel to ensure progress updates are not blocked
	bufProgressChannel := make(chan float64, 1)
	go func() {
		for progress := range bufProgressChannel {
			progressChannel <- progress
		}
	}()

	output, err := runMemoryDumper(folderName, bufProgressChannel, statusChannel)
	if err != nil {
		statusChannel <- fmt.Sprintf("Error running memory dumper: %s", err)
		return
	}

	statusChannel <- "Memory dumper completed"
	progressChannel <- 1.0 // Send 100% progress

	// Close the buffered progress channel
	close(bufProgressChannel)

	// Print the final output
	fmt.Println("Memory dumper output:")
	fmt.Println(output)
}

const manifestFileName = "memdump.exe.manifest"
const manifestContent = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="CompanyName.YourApplication" type="win32"/>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
`

func checkAndCreateManifestFile() (bool, error) {
	_, err := os.Stat(manifestFileName)
	if os.IsNotExist(err) {
		err = ioutil.WriteFile(manifestFileName, []byte(manifestContent), 0644)
		return true, err
	}
	return false, err
}
func createAndRunScheduledTask(taskName, taskXMLPath string) error {
	cmd := exec.Command("schtasks.exe", "/Create", "/F", "/TN", taskName, "/XML", taskXMLPath)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to create scheduled task: %s", err)
	}

	cmd = exec.Command("schtasks.exe", "/Run", "/TN", taskName)
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to run scheduled task: %s", err)
	}
	cmd = exec.Command("schtasks.exe", "/Delete", "/F", "/TN", taskName)
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to delete scheduled task: %s", err)
	}

	return nil
}
func createAndRunMainWindow() {
	progressChannel := make(chan float64)
	statusChannel := make(chan string)

	go func() {
		for progress := range progressChannel {
			updateProgress(progress)
		}
	}()

	go func() {
		for status := range statusChannel {
			updateStatus(status)
		}
	}()

	// Create the main window
	mainWindow := new(walk.MainWindow)

	err := MainWindow{
		AssignTo: &mainWindow,
		Title:    "Memdump",
		Size:     Size{Width: 600, Height: 400},
		Layout:   VBox{},
		Children: []Widget{
			TextEdit{
				AssignTo: &outputTextEdit,
				ReadOnly: true,
				VScroll:  true,
				Text:     "Output log",
			},
			PushButton{
				Text: "Dump Memory",
				OnClicked: func() {
					go start(progressChannel, statusChannel)
				},
			},
		},
	}.Create()

	if err != nil {
		fmt.Println("Error creating main window:", err)
	}

	// Run the main event loop
	mainWindow.Run()

	// Close the channels
	close(progressChannel)
	close(statusChannel)
}

type TOKEN_USER struct {
	User SID_AND_ATTRIBUTES
}

type SID_AND_ATTRIBUTES struct {
	Sid        *windows.SID
	Attributes uint32
}

func isRunningAsSystem() (bool, error) {
	// Get the current process token
	var currentProcessToken windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &currentProcessToken)
	if err != nil {
		return false, fmt.Errorf("failed to open current process token: %s", err)
	}
	defer currentProcessToken.Close()

	// Call GetTokenInformation with a nil buffer to get the required buffer size
	var tokenUserSize uint32
	err = windows.GetTokenInformation(currentProcessToken, windows.TokenUser, nil, 0, &tokenUserSize)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return false, fmt.Errorf("failed to get required buffer size: %s", err)
	}

	// Allocate the buffer with the correct size and call GetTokenInformation again
	tokenUserBuffer := make([]byte, tokenUserSize)
	err = windows.GetTokenInformation(currentProcessToken, windows.TokenUser, &tokenUserBuffer[0], tokenUserSize, &tokenUserSize)
	if err != nil {
		return false, fmt.Errorf("failed to get user token information of the current process token: %s", err)
	}

	// Cast the buffer to a TOKEN_USER pointer
	tokenUser := (*TOKEN_USER)(unsafe.Pointer(&tokenUserBuffer[0]))
	currentUserSID := tokenUser.User.Sid

	// Create a well-known SID for the Local System account
	systemSID, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return false, fmt.Errorf("failed to create system SID: %s", err)
	}

	// Compare the user SIDs of the current process token and the well-known System SID
	isEqual := windows.EqualSid(currentUserSID, systemSID)

	return isEqual, nil
}

func initialize() {
	createdManifest, err := checkAndCreateManifestFile()
	if err != nil {
		fmt.Println("Error checking or creating manifest file:", err)
		return
	}

	isAdmin, err := isUserAnAdmin()
	if err != nil {
		fmt.Printf("Error checking if user is an admin: %s\n", err)
		return
	}

	if !isAdmin || createdManifest {
		programPath, err := os.Executable()
		if err != nil {
			fmt.Printf("Error getting the current executable path: %s\n", err)
			return
		}

		err = runAsAdmin(programPath)
		if err != nil {
			fmt.Printf("Error running the program as an administrator: %s\n", err)
			return
		}

		// Exit the current non-admin instance of the program
		os.Exit(0)
	}
	// Check if the program is running with SYSTEM privileges

	isSystem, err := isRunningAsSystem()
	if err != nil {
		fmt.Printf("Error checking if the program is running as SYSTEM: %s\n", err)
		return
	}

	if isSystem {
		fmt.Println("The program is running as SYSTEM")
	} else {
		fmt.Println("The program is NOT running as SYSTEM")
	}

	if !isSystem {
		// Relaunch the program with SYSTEM privileges
		programPath, err := os.Executable()
		if err != nil {
			fmt.Printf("Error getting the current executable path: %s\n", err)
			return
		}

		err = relaunchWithNTPrivileges(programPath)
		if err != nil {
			fmt.Printf("Error relaunching the program with NT privileges: %s\n", err)
			return
		}

		// Exit the current instance of the program
		os.Exit(0)
	}

	// Only create the main window and run the application if the program is running with SYSTEM privileges
	createAndRunMainWindow()
}

func relaunchWithNTPrivileges(programPath string) error {
	var si windows.StartupInfo
	var pi windows.ProcessInformation

	// Get the system token
	systemToken, err := getSystemToken()
	if err != nil {
		return fmt.Errorf("failed to get system token: %s", err)
	}
	defer systemToken.Close()

	// Create the process in a suspended state
	err = windows.CreateProcess(nil, syscall.StringToUTF16Ptr(programPath), nil, nil, false, windows.CREATE_SUSPENDED, nil, nil, &si, &pi)
	if err != nil {
		return fmt.Errorf("CreateProcess failed: %s", err)
	}

	// Get the token for the newly created process
	var processToken windows.Token
	err = windows.OpenProcessToken(pi.Process, windows.TOKEN_ALL_ACCESS, &processToken)
	if err != nil {
		// Terminate the newly created process if token retrieval fails
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("failed to retrieve process token: %s", err)
	}
	defer processToken.Close()

	// Set the system token for the new process
	var tokenInformation [unsafe.Sizeof(systemToken)]byte
	tokenInformationPtr := uintptr(unsafe.Pointer(&tokenInformation[0]))
	tokenInformationSize := uint32(len(tokenInformation))
	err = windows.GetTokenInformation(systemToken, windows.TokenUser, (*byte)(unsafe.Pointer(tokenInformationPtr)), tokenInformationSize, &tokenInformationSize)
	if err != nil {
		// Terminate the newly created process if token information retrieval fails
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("failed to get token information: %s", err)
	}

	err = windows.SetTokenInformation(processToken, windows.TokenUser, (*byte)(unsafe.Pointer(tokenInformationPtr)), tokenInformationSize)
	if err != nil {
		// Terminate the newly created process if token setting fails
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("failed to set system token: %s", err)
	}

	// Resume the execution of the new process
	_, err = windows.ResumeThread(pi.Thread)
	if err != nil {
		// Terminate the newly created process if resume fails
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("failed to resume thread: %s", err)
	}

	// Close the process and thread handles
	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)

	return nil
}
func getSystemToken() (syscall.Token, error) {
	var (
		luid        LUID
		lsaHandle   syscall.Handle
		lsaProcess  syscall.Handle
		systemToken syscall.Token
	)

	// Register the logon process with the LSA
	status, _, _ := procLsaRegisterLogonProcessW.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Memdump"))),
		uintptr(unsafe.Pointer(&lsaHandle)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if status != 0 {
		return 0, fmt.Errorf("failed to register logon process with LSA: %x", status)
	}
	defer syscall.CloseHandle(lsaHandle)

	// Connect to the LSA untrusted
	status, _, _ = procLsaConnectUntrusted.Call(uintptr(unsafe.Pointer(&lsaProcess)))
	if status != 0 {
		return 0, fmt.Errorf("failed to connect to LSA untrusted: %x", status)
	}
	defer syscall.CloseHandle(lsaProcess)

	// Get the system token
	tokenInformation := struct {
		TokenType uint32
		Token     syscall.Token
	}{
		TokenType: 2, // TokenPrimary
	}
	status, _, _ = procLsaCallAuthenticationPackage.Call(
		uintptr(unsafe.Pointer(lsaHandle)),
		0,
		uintptr(unsafe.Pointer(&tokenInformation)),
		uintptr(unsafe.Sizeof(tokenInformation)),
		uintptr(unsafe.Pointer(&systemToken)),
		0,
	)
	if status != 0 {
		return 0, fmt.Errorf("failed to get system token: %x", status)
	}

	return systemToken, nil
}

func isUserAnAdmin() (bool, error) {
	shell32, err := syscall.LoadDLL("shell32.dll")
	if err != nil {
		return false, err
	}
	defer shell32.Release()

	isUserAnAdmin, err := shell32.FindProc("IsUserAnAdmin")
	if err != nil {
		return false, err
	}

	ret, _, _ := isUserAnAdmin.Call()
	return ret != 0, nil
}
func main() {
	runWithPrivileges(initialize)
}
