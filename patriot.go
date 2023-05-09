package main

import (
	"bufio"
	"bytes"
	"fmt"
	"image/color"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unsafe"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/sys/windows"
)

var myApp fyne.App
var myWindow fyne.Window

type DriverPackage struct {
	DriverName        string
	PublishedName     string
	DriverVersion     string
	PackageRanking    string
	OEMInformation    string
	DriverDisplayName string
}

const (
	PROCESS_ALL_ACCESS = 0x1F0FFF
	MEM_COMMIT         = 0x1000
)

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
type WMICApp struct {
	Name string
	GUID string
}

func setMemory(ptr unsafe.Pointer, value byte, size uintptr) {
	bytes := make([]byte, size)
	for i := range bytes {
		bytes[i] = value
	}
	copy((*[1 << 30]byte)(ptr)[:size:size], bytes)
}

var (
	modkernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	modpsapi                     = windows.NewLazySystemDLL("psapi.dll")
	procCreateToolhelp32Snapshot = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = modkernel32.NewProc("Process32FirstW")
	procProcess32Next            = modkernel32.NewProc("Process32NextW")
	procOpenProcess              = modkernel32.NewProc("OpenProcess")
	procReadProcessMemory        = modkernel32.NewProc("ReadProcessMemory")
	procGetProcessMemoryInfo     = modpsapi.NewProc("GetProcessMemoryInfo")
	procVirtualQueryEx           = modkernel32.NewProc("VirtualQueryEx")
)

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
func createToolhelp32Snapshot() (syscall.Handle, error) {
	ret, _, err := procCreateToolhelp32Snapshot.Call(uintptr(0x2), uintptr(0x0))
	if ret == uintptr(syscall.InvalidHandle) {
		return syscall.InvalidHandle, err
	}
	return syscall.Handle(ret), nil
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
	for _, memRange := range memoryRanges {
		protectionStr := protectionFlagsToString(memRange.Protect)
		log.Printf("Base address: %X, Region size: %X, Protection: %s\n", memRange.BaseAddress, memRange.RegionSize, protectionStr)
	}

	return nil
}
func execCommandWithPrompt(command string, args ...string) {
	cmd := exec.Command(command, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}
func enumerateDriverPackages() ([]DriverPackage, error) {
	driverPackages := make([]DriverPackage, 0)

	cmd := exec.Command("pnputil", "-e")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate driver packages: %v", err)
	}

	re := regexp.MustCompile(`Published name\s+:\s+(.+)\r?\nDriver package provider\s+:\s+(.+)\r?\nClass\s+:\s+(.+)\r?\nDriver date and version\s+:\s+(.+)\r?\nDriver package ranking\s+:\s+(.+)\r?\nOEM information\s+:\s+(.+)\r?\n`)

	matches := re.FindAllStringSubmatch(string(output), -1)

	for _, match := range matches {
		driverPackage := DriverPackage{
			DriverName:    match[2],
			PublishedName: match[1],
		}
		driverPackages = append(driverPackages, driverPackage)
	}

	return driverPackages, nil
}
func execCommand(logOutput *widget.Entry, command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...)
	outputBytes, err := cmd.CombinedOutput()
	output := string(outputBytes)
	if err != nil {
		logOutput.SetText(logOutput.Text + "Error: " + err.Error() + "\n")
		return "", err
	}
	logOutput.SetText(logOutput.Text + "Output: " + output + "\n")
	return output, nil
}

func (d DriverPackage) String() string {
	return fmt.Sprintf("Published name: %s, Driver name: %s", d.PublishedName, d.DriverName)
}
func getDriverPackages(logOutput *widget.Entry) ([]DriverPackage, []string, error) {
	var driverPackages []DriverPackage
	var driverPackageIds []string

	// Get list of driver packages and IDs
	command := "pnputil /e"
	out, err := exec.Command("cmd", "/C", command).Output()
	if err != nil {
		return nil, nil, err
	}

	// Parse output and extract driver package information
	re := regexp.MustCompile(`Published name\s+:\s*(.+)\r\nDriver package provider\s+:\s*(.+)\r\nClass\s+:\s*(.+)\r\nDriver date and version\s+:\s*(.+)\r\nSigner name\s+:\s*(.+)(?:\r\nRank\s+:\s*(.+))?(?:\r\nOEM\s+:\s*(.+))?`)
	matches := re.FindAllStringSubmatch(string(out), -1)

	for _, match := range matches {
		driverPackage := DriverPackage{
			DriverName:        match[3],
			PublishedName:     match[1],
			DriverVersion:     match[4],
			PackageRanking:    match[5],
			OEMInformation:    match[6],
			DriverDisplayName: "",
		}
		driverPackages = append(driverPackages, driverPackage)
		driverPackageIds = append(driverPackageIds, match[1])
	}

	// Get the driver display names
	commandEnumDrivers := "pnputil /enum-drivers"
	outEnumDrivers, err := exec.Command("cmd", "/C", commandEnumDrivers).Output()
	if err != nil {
		return nil, nil, err
	}

	// Parse output and extract driver display names
	reEnumDrivers := regexp.MustCompile(`(?m)Published Name:\s*(.+)\r?\nOriginal Name:\s*(.+)\r?\nProvider Name:`)
	matchesEnumDrivers := reEnumDrivers.FindAllStringSubmatch(string(outEnumDrivers), -1)
	driverDisplayNames := make(map[string]string)
	for _, match := range matchesEnumDrivers {
		publishedName := strings.TrimSpace(match[1])
		originalName := strings.TrimSpace(match[2])
		driverDisplayNames[publishedName] = originalName
	}
	// Match published name with driver name
	for i, driverPackage := range driverPackages {
		if displayName, ok := driverDisplayNames[driverPackage.PublishedName]; ok {
			driverPackages[i].DriverDisplayName = displayName
		}
	}
	return driverPackages, driverPackageIds, nil
}
func execCommandWithUserInput(cmdName string, args ...string) (string, error) {
	cmd := exec.Command(cmdName, args...)
	// Set command's stdin to os.Stdin to accept user input
	cmd.Stdin = os.Stdin

	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	err := cmd.Run()
	if err != nil {
		return "", err
	}

	return out.String(), nil
}

func getWMICApps(logOutput *widget.Entry) ([]WMICApp, error) {
	command := "wmic product get IdentifyingNumber, Name /format:list"
	output, err := exec.Command("cmd", "/C", command).Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	apps := make([]WMICApp, 0)

	var currentApp WMICApp
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			if currentApp.GUID != "" && currentApp.Name != "" {
				apps = append(apps, currentApp)
			}
			currentApp = WMICApp{}
			continue
		}

		keyValue := strings.SplitN(line, "=", 2)
		if len(keyValue) == 2 {
			key := strings.TrimSpace(keyValue[0])
			value := strings.TrimSpace(keyValue[1])

			switch key {
			case "IdentifyingNumber":
				currentApp.GUID = value
			case "Name":
				currentApp.Name = value
			}
		}
	}

	if currentApp.GUID != "" && currentApp.Name != "" {
		apps = append(apps, currentApp)
	}

	return apps, nil
}

func getWindowsStoreApps(logOutput *widget.Entry) ([]string, error) {
	storeApps := []string{}
	output, err := execCommand(logOutput, "powershell", "-command", "Get-AppxPackage -AllUsers | Format-Table Name,PackageFullName -AutoSize")
	if err != nil {
		return nil, err
	}
	input := strings.NewReader(output)
	scanner := bufio.NewScanner(input)
	scanner.Scan() // Skip the header line
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			delimiter := strings.Index(line, "  ")
			if delimiter != -1 {
				appName := line[:delimiter]
				appFullName := strings.TrimSpace(line[delimiter+2:])
				storeApps = append(storeApps, appName+","+appFullName)
			}
		}
	}
	return storeApps, nil
}

func performSystemCleanup(progressChan chan float64, doneChan chan bool, progressBar *widget.ProgressBar, logOutput *widget.Entry) {
	totalSteps := 24 // for example, you can divide the whole process into 10 steps
	stepProgress := 100.0 / float64(totalSteps)
	fmt.Println("Performing full cleanup and system file check.")
	output, err := execCommand(logOutput, "dism", "/online", "/cleanup-image", "/startcomponentcleanup")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	output, err = execCommand(logOutput, "dism", "/online", "/cleanup-image", "/restorehealth")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	output, err = execCommand(logOutput, "sfc", "/scannow")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	fmt.Println("Deleting Prefetch files.")
	systemRoot := os.ExpandEnv("%systemroot%")
	output, err = execCommand(logOutput, "cmd", "/c", "del /s /q /f", systemRoot+"\\Prefetch\\*")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	fmt.Println("Cleaning up Windows Update cache.")
	progressChan <- stepProgress
	output, err = execCommand(logOutput, "net", "stop", "wuauserv")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	output, err = execCommand(logOutput, "net", "stop", "bits")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	output, err = execCommand(logOutput, "cmd", "/c", "rd /s /q", systemRoot+"\\SoftwareDistribution")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	output, err = execCommand(logOutput, "net", "start", "wuauserv")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	output, err = execCommand(logOutput, "net", "start", "bits")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	fmt.Println("Performing disk cleanup.")
	progressChan <- stepProgress
	output, err = execCommand(logOutput, "cleanmgr", "/sagerun:1")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	fmt.Println("Removing temporary files.")
	progressChan <- stepProgress
	temp := os.ExpandEnv("%temp%")
	output, err = execCommand(logOutput, "del", "/s /q", temp+"\\*")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	output, err = execCommand(logOutput, "del", "/s /q", systemRoot+"\\temp\\*")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	fmt.Println("Cleaning up font cache.")
	progressChan <- stepProgress
	output, err = execCommand(logOutput, "net", "stop", "fontcache")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	output, err = execCommand(logOutput, "del", "/f /s /q /a", systemRoot+"\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache\\*")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	output, err = execCommand(logOutput, "del", "/f /s /q /a", systemRoot+"\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache-System\\*")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	output, err = execCommand(logOutput, "net", "start", "fontcache")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	//disable insecure windows features
	fmt.Println("Disabling insecure windows features.")
	progressChan <- stepProgress
	output, err = execCommand(logOutput, "dism", "/online", "/disable-feature", "/featurename:WindowsMediaPlayer")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	fmt.Println("Disabling Windows Media Player")
	output, err = execCommand(logOutput, "dism", "/online", "/disable-feature", "/featurename:WindowsMediaPlayer")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	fmt.Println("Disabling SMBV1")
	output, err = execCommand(logOutput, "dism", "/online", "/disable-feature", "/featurename:SMB1Protocol")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	fmt.Println("Disabling RDP")
	output, err = execCommand(logOutput, "reg", "add", "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "1", "/f")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	fmt.Println("Disabling Remote Assistance")
	output, err = execCommand(logOutput, "reg", "add", "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance", "/v", "fAllowToGetHelp", "/t", "REG_DWORD", "/d", "0", "/f")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	fmt.Println("Disable Autorun for all drives")
	output, err = execCommand(logOutput, "reg", "add", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "/v", "NoDriveTypeAutoRun", "/t", "REG_DWORD", "/d", "255", "/f")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	fmt.Println("Disabling LLMNR")
	output, err = execCommand(logOutput, "reg", "add", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "/v", "EnableMulticast", "/t", "REG_DWORD", "/d", "0", "/f")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	//fmt.Println("Deleting oldest shadowcopy")
	//output, err := execCommand(logOutput, "vssadmin", "delete", "shadows", "/for=C:", "/oldest")
	//if err == nil {
	//logOutput.SetText(logOutput.Text + output)
	//progressChan <- stepProgress
	fmt.Println("Enable UAC")
	output, err = execCommand(logOutput, "reg", "add", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "/v", "EnableLUA", "/t", "REG_DWORD", "/d", "1", "/f")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	output, err = execCommand(logOutput, "reg", "add", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "/v", "ConsentPromptBehaviorAdmin", "/t", "REG_DWORD", "/d", "2", "/f")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	fmt.Println("Deleting log files older than 7 days")
	output, err = execCommand(logOutput, "forfiles", "/p", "C:\\Windows\\Logs", "/s", "/m", "*.log", "/d", "-7", "/c", "cmd /c del @path")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	fmt.Println("Enabling Windows Defender Credential Guard")
	fmt.Println("Enabling Credential Guard.")
	output, err = execCommand(logOutput, "reg", "add", "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\LSA", "/v", "LsaCfgFlags", "/t", "REG_DWORD", "/d", "1", "/f")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	progressChan <- stepProgress
	output, err = execCommand(logOutput, "bcdedit", "/set", "{0cb3b571-2f2e-4343-a879-d86a476d7215}", "loadoptions", "DISABLE-LSA-ISO,DISABLE-VSM")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	output, err = execCommand(logOutput, "bcdedit", "/set", "{0cb3b571-2f2e-4343-a879-d86a476d7215}", "device", "path", "\\EFI\\Microsoft\\Boot\\SecConfig.efi")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	fmt.Println("Enabling Exploit Protection settings")
	progressChan <- stepProgress
	output, err = execCommand(logOutput, "powershell", "-command", "Set-ProcessMitigation -System -Enable DEP,SEHOP")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	fmt.Println("Enabling Data Execution Prevention (DEP)")
	progressChan <- stepProgress
	output, err = execCommand(logOutput, "bcdedit", "/set", "nx", "AlwaysOn")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	fmt.Println("Enabling Secure Boot")
	output, err = execCommand(logOutput, "bcdedit", "/set", "{default}", "bootmenupolicy", "Standard")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	fmt.Println("Enabling secure boot-step 2.")
	output, err = execCommand(logOutput, "powershell", "-command", "Confirm-SecureBootUEFI")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	fmt.Println("Disabling Microsoft Office macros.")
	output, err = execCommand(logOutput, "reg", "add", "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Excel\\Security", "/v", "VBAWarnings", "/t", "REG_DWORD", "/d", "4", "/f")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	output, err = execCommand(logOutput, "reg", "add", "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\PowerPoint\\Security", "/v", "VBAWarnings", "/t", "REG_DWORD", "/d", "4", "/f")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	output, err = execCommand(logOutput, "reg", "add", "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Word\\Security", "/v", "VBAWarnings", "/t", "REG_DWORD", "/d", "4", "/f")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	fmt.Println("Enabling Address Space Layout Randomization.")
	output, err = execCommand(logOutput, "reg", "add", "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", "/v", "MoveImages", "/t", "REG_DWORD", "/d", "1", "/f")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	fmt.Println("Enabling Windows Defender Real-Time protection VIA registry.")
	output, err = execCommand(logOutput, "reg", "add", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender", "/v", "DisableAntiSpyware", "/t", "REG_DWORD", "/d", "0", "/f")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	output, err = execCommand(logOutput, "reg", "add", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "/v", "DisableBehaviorMonitoring", "/t", "REG_DWORD", "/d", "0", "/f")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	output, err = execCommand(logOutput, "reg", "add", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "/v", "DisableOnAccessProtection", "/t", "REG_DWORD", "/d", "0", "/f")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	output, err = execCommand(logOutput, "reg", "add", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "/v", "DisableScanOnRealtimeEnable", "/t", "REG_DWORD", "/d", "0", "/f")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	fmt.Println("Enabling DNS-over-HTTPS (DoH) in Windows 11.")
	output, err = execCommand(logOutput, "reg", "add", "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters", "/v", "EnableAutoDoh", "/t", "REG_DWORD", "/d", "2", "/f")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	fmt.Println("Checking for and installing Windows updates.")
	progressChan <- stepProgress
	output, err = execCommand(logOutput, "powershell", "-ep", "bypass", "-command", "Install-Module -Name PackageProvider -Force")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	output, err = execCommandWithUserInput("powershell", "-ExecutionPolicy", "Bypass", "-command", "Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}

	output, err = execCommandWithUserInput("powershell", "-ExecutionPolicy", "Bypass", "-command", "Install-Module -Name PowerShellGet -Scope CurrentUser -Force -AllowClobber")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}

	output, err = execCommandWithUserInput("powershell", "-ExecutionPolicy", "Bypass", "-command", "Register-PackageSource -Trusted -ProviderName 'PowerShellGet' -Name 'PSGallery' -Location 'https://www.powershellgallery.com/api/v2'")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}

	output, err = execCommandWithUserInput("powershell", "-ExecutionPolicy", "Bypass", "-command", "Install-Package -Name PSWindowsUpdate -ProviderName PowerShellGet -Force")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}

	output, err = execCommandWithUserInput("powershell", "-ExecutionPolicy", "Bypass", "-command", "Import-Module PowerShellGet; Import-Module PSWindowsUpdate; Install-Module PSWindowsUpdate -Force; Get-WindowsUpdate -Install")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}

	fmt.Println("Restricting access to the Local System Authority.")
	output, err = execCommand(logOutput, "reg", "add", "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "/v", "RestrictAnonymous", "/t", "REG_DWORD", "/d", "1", "/f")
	// Disable Windows Delivery Optimization
	fmt.Println("Disabling Windows Delivery Optimization")
	progressChan <- stepProgress
	output, err = execCommand(logOutput, "reg", "add", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization", "/v", "DODownloadMode", "/t", "REG_DWORD", "/d", "0", "/f")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	fmt.Println("Enabling Memory Integrity")
	output, err = execCommand(logOutput, "reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\\", "/v", "Enabled", "/t", "REG_DWORD", "/d", "1", "/f")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	fmt.Println("Emptying Recycling Bin")
	bin := os.ExpandEnv("%systemdrive")
	output, err = execCommand(logOutput, "rd", "/s /q", bin+"\\$Recycle.Bin")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	fmt.Println("Enabling Kernel Mode Hardware Enforced Stack Protection.")
	output, err = execCommand(logOutput, "bcdedit", "/set", "kstackguardpolicy", "enable")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	fmt.Println("Enabling Windows Defender and Security Center.")
	// Enabling Windows Security Center
	fmt.Println("Enabling Windows Security Center service")
	output, err = execCommand(logOutput, "sc", "config", "wscsvc", "start=", "auto")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	output, err = execCommand(logOutput, "sc", "start", "wscsvc")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	// Updating Windows Defender signatures
	fmt.Println("Updating Windows Defender signatures.")
	output, err = execCommand(logOutput, "powershell.exe", "Update-MpSignature")
	if err == nil {
		logOutput.SetText(logOutput.Text + output)
	}
	doneChan <- true
}

type CustomTheme struct {
	originalTheme fyne.Theme
}

func (c CustomTheme) ForegroundColor() color.Color {
	return color.White
}

func (c CustomTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	return c.originalTheme.Color(name, variant)
}

func (c CustomTheme) Font(style fyne.TextStyle) fyne.Resource {
	return c.originalTheme.Font(style)
}

func (c CustomTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return c.originalTheme.Icon(name)
}

func (c CustomTheme) Size(name fyne.ThemeSizeName) float32 {
	return c.originalTheme.Size(name)
}
func newCustomTheme(baseTheme fyne.Theme) fyne.Theme {
	return &CustomTheme{originalTheme: baseTheme}
}

func (c CustomTheme) ButtonColor() color.Color {
	return color.Black
}

type Theme interface {
	BackgroundColor() color.Color
	ButtonColor() color.Color
	DisabledButtonColor() color.Color
	DisabledTextColor() color.Color
	ForegroundColor() color.Color
	HoverColor() color.Color
	PlaceHolderColor() color.Color
	PrimaryColor() color.Color
	ScrollBarColor() color.Color
	ShadowColor() color.Color
	TextSize() int
	TextFont() fyne.Resource
	TextBoldFont() fyne.Resource
	TextItalicFont() fyne.Resource
	TextBoldItalicFont() fyne.Resource
	TextMonospaceFont() fyne.Resource
	Padding() int
	IconInlineSize() int
	ScrollBarSize() int
	ScrollBarSmallSize() int
}

func main() {
	fmt.Println("(-)Booting up the Patriot... please wait X) -- Coded By Harrison Edwards")
	os.Setenv("FYNE_RENDER", "software")
	myApp := app.New()
	myApp.Settings().SetTheme(theme.DarkTheme())
	myWindow := myApp.NewWindow("The Patriot")
	progressBar := widget.NewProgressBar()
	numCommands := 18
	progressBar.Max = float64(numCommands)

	logOutput := widget.NewEntry()
	logOutput.MultiLine = true
	logOutput.Disable()

	driverPackages, _, _ := getDriverPackages(logOutput)
	logOutputContainer := container.NewScroll(logOutput)
	storeApps, _ := getWindowsStoreApps(logOutput)
	// System cleanup button
	cleanupButton := widget.NewButton("Perform System Cleanup", func() {
		progressBar.SetValue(0)
		progressBar.Show()
		progressChan := make(chan float64)
		doneChan := make(chan bool)
		go func() {
			for progress := range progressChan {
				currentProgress := progressBar.Value
				progressBar.SetValue(currentProgress + progress)
			}
		}()

		go performSystemCleanup(progressChan, doneChan, progressBar, logOutput)
		go func() {
			<-doneChan
			progressBar.Hide()
			fmt.Println("System cleanup completed.")
			close(progressChan)
		}()
	})
	progressBar.Hide()
	cleanupTab := container.NewVBox(
		cleanupButton,
		widget.NewLabel("Click the button to perform system cleanup."),
		progressBar,
	)
	cleanupTab.Resize(fyne.NewSize(800, 600)) // set a fixed size for the cleanupTab container

	// List of Windows Store Apps
	storeAppList := widget.NewList(
		func() int {
			return len(storeApps)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("Template")
		},
		func(index widget.ListItemID, item fyne.CanvasObject) {
			item.(*widget.Label).SetText(storeApps[index])
		},
	)
	storeAppList.OnSelected = func(id widget.ListItemID) {
		appFullName := storeApps[id]
		command := "powershell -command \"Get-AppxPackage -AllUsers -Name " + appFullName + " | Remove-AppxPackage\""
		logOutput.SetText(logOutput.Text + "Uninstalling Windows Store app: " + appFullName + "\n")

		output, err := exec.Command("cmd", "/C", command).CombinedOutput()
		if err != nil {
			logOutput.SetText(logOutput.Text + "Error: " + err.Error() + "\n")
		} else {
			logOutput.SetText(logOutput.Text + "Output: " + string(output) + "\n")
		}
		storeApps, _ = getWindowsStoreApps(logOutput)
		storeAppList.Refresh()
	}
	// List of Driver Packages
	driverPackageList := widget.NewList(
		func() int {
			return len(driverPackages)
		},
		func() fyne.CanvasObject {
			return container.NewVBox(
				container.NewHBox(
					widget.NewLabel("Driver Display Name: "),
					widget.NewLabel("Template"),
				),
				container.NewHBox(
					widget.NewLabel("Driver Name: "),
					widget.NewLabel("Template"),
				),
				container.NewHBox(
					widget.NewLabel("Published Name: "),
					widget.NewLabel("Template"),
				),
				container.NewHBox(
					widget.NewLabel("Driver Version: "),
					widget.NewLabel("Template"),
				),
			)
		},
		func(index widget.ListItemID, item fyne.CanvasObject) {
			vbox := item.(*fyne.Container)
			driverDisplayNameLabel := vbox.Objects[0].(*fyne.Container).Objects[1].(*widget.Label)
			driverNameLabel := vbox.Objects[1].(*fyne.Container).Objects[1].(*widget.Label)
			publishedNameLabel := vbox.Objects[2].(*fyne.Container).Objects[1].(*widget.Label)
			driverVersionLabel := vbox.Objects[3].(*fyne.Container).Objects[1].(*widget.Label)

			driverDisplayNameLabel.SetText(driverPackages[index].DriverDisplayName)
			driverNameLabel.SetText(driverPackages[index].DriverName)
			publishedNameLabel.SetText(driverPackages[index].PublishedName)
			driverVersionLabel.SetText(driverPackages[index].DriverVersion)
		},
	)

	driverPackageList.OnSelected = func(id widget.ListItemID) {
		driverPackageName := driverPackages[id].PublishedName
		command := "/d \"" + driverPackageName + "\""
		logOutput.SetText(logOutput.Text + "Deleting driver package: " + driverPackageName + "\n")

		// Use execCommandWithPrompt to request administrative privileges
		execCommandWithPrompt("pnputil.exe", command)

		driverPackages, _, _ = getDriverPackages(logOutput)
		driverPackageList.Refresh()
	}

	// List of WMIC Apps
	wmicApps, _ := getWMICApps(logOutput)
	wmicAppList := widget.NewList(
		func() int {
			return len(wmicApps)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("Template")
		},
		func(index widget.ListItemID, item fyne.CanvasObject) {
			item.(*widget.Label).SetText(wmicApps[index].Name + " (" + wmicApps[index].GUID + ")")
		},
	)

	wmicAppList.OnSelected = func(id widget.ListItemID) {
		appId := wmicApps[id].GUID
		appName := wmicApps[id].Name
		command := "wmic"
		args := []string{"product", "where", "Caption='" + appName + "'", "call", "uninstall"}

		logOutput.SetText(logOutput.Text + "Uninstalling WMIC app: " + appName + " (" + appId + ")\n")

		execCommandWithPrompt(command, args...)

		wmicAppList.Refresh()
	}

	// Create a new progress bar for the memory dump tab
	dumpProgress := widget.NewProgressBar()
	dumpProgress.Resize(fyne.NewSize(400, 10))
	outputLabel := widget.NewLabel("")
	scrollContainer := container.NewScroll(outputLabel)
	// Create a new button for the memory dump tab
	dumpButton := widget.NewButton("Dump Memory", func() {
		entry := widget.NewEntry()
		entry.SetPlaceHolder("Enter folder name")

		confirm := func(response bool) {
			if response {
				folderName := entry.Text
				if folderName != "" {
					err := os.MkdirAll(folderName, 0755)
					if err != nil {
						logOutput.SetText(fmt.Sprintf("Error creating folder: %v", err))
						return
					}
				}

				progressChannel := make(chan float64)
				statusChannel := make(chan string)

				go func() {
					output, err := runMemoryDumper(folderName, progressChannel, statusChannel)
					if err != nil {
						logOutput.SetText(fmt.Sprintf("Error: %v", err))
					} else {
						logOutput.SetText(output)
					}
				}()

				go func() {
					for {
						select {
						case progressValue := <-progressChannel:
							progressBar.SetValue(progressValue)
						case status := <-statusChannel:
							// Append the status update to the logOutput
							existingText := logOutput.Text
							logOutput.SetText(existingText + status)
						}
					}
				}()

			}
		}

		dialog.ShowCustomConfirm("Create Folder", "Create", "Cancel", entry, confirm, myWindow)
	})

	dumpTab := container.NewVBox(
		dumpButton,
		widget.NewLabel("Click the button to dump memory."),
		progressBar,
		scrollContainer,
	)
	logTab := container.NewTabItem("Log Output", logOutputContainer)
	tabs := container.NewAppTabs(
		container.NewTabItem("Windows Store Apps", storeAppList),
		container.NewTabItem("Driver Packages", driverPackageList),
		container.NewTabItem("WMIC Apps", wmicAppList),
		container.NewTabItem("System Cleanup", cleanupTab),
		logTab,
	)
	tabs.Append(container.NewTabItem("Memory Dump", dumpTab))
	myWindow.SetContent(tabs)
	myWindow.Resize(fyne.NewSize(800, 600))
	myWindow.ShowAndRun()
}
