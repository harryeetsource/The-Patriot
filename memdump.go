package main

import (
	// Import necessary packages
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/kardianos/service"
	"golang.org/x/sys/windows"
)

const (
	SE_DEBUG_NAME              = "SeDebugPrivilege"
	SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege"
	SE_LOAD_DRIVER_NAME        = "SeLoadDriverPrivilege"
	SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege"
	SE_TAKE_OWNERSHIP_NAME     = "SeTakeOwnershipPrivilege"
	SE_TCB_NAME                = "SeTcbPrivilege"
	SE_SHUTDOWN_PRIVILEGE      = "SeShutdownPrivilege"
)

var (
	modSecur32                       = syscall.NewLazyDLL("secur32.dll")
	modkernel32                      = windows.NewLazySystemDLL("kernel32.dll")
	modAdvapi32                      = syscall.NewLazyDLL("advapi32.dll")
	procLsaRegisterLogonProcessW     = modSecur32.NewProc("LsaRegisterLogonProcess")
	procLsaConnectUntrusted          = modSecur32.NewProc("LsaConnectUntrusted")
	procLsaCallAuthenticationPackage = modSecur32.NewProc("LsaCallAuthenticationPackage")
	procLsaFreeReturnBuffer          = modSecur32.NewProc("LsaFreeReturnBuffer")
)

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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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

type TOKEN_USER struct {
	User SID_AND_ATTRIBUTES
}

type SID_AND_ATTRIBUTES struct {
	Sid        *windows.SID
	Attributes uint32
}
type program struct{}

func (p *program) Start(s service.Service) error {
	go p.run()
	return nil
}
func isProcessRunningAsSystem(process *os.Process) (bool, error) {
	processHandle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(process.Pid))
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(processHandle)

	var processToken windows.Token
	err = windows.OpenProcessToken(processHandle, windows.TOKEN_QUERY, &processToken)
	if err != nil {
		return false, err
	}
	defer processToken.Close()

	var tokenUser *windows.Tokenuser
	tokenUser, err = processToken.GetTokenUser()
	if err != nil {
		return false, err
	}

	systemSid, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return false, err
	}

	return windows.EqualSid(tokenUser.User.Sid, systemSid), nil
}

func (p *program) run() {
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

	// Proceed with retrieving the memdump-gui.exe path
	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get current executable path: %v", err)
	}

	// Get the directory containing the current executable
	execDir := filepath.Dir(execPath)

	// Build the path to memdump-gui.exe
	memdumpGUIPath := filepath.Join(execDir, "memdump-gui.exe")

	// Get the system token
	systemToken, err := getSystemToken()
	if err != nil {
		log.Fatalf("Failed to get system token: %v", err)
	}

	// Launch memdump-gui.exe with NT privileges
	guiProcess, err := relaunchWithNTPrivileges(memdumpGUIPath, windows.Token(systemToken))
    if err != nil {
        log.Fatalf("Failed to launch memdump-gui.exe with NT privileges: %v", err)

	// Check if the memdump-gui process is running with SYSTEM privileges
	guiProcess, err := os.FindProcess(guiProcessID)
	if err != nil {
		fmt.Printf("Error finding the memdump-gui process: %s\n", err)
		return
	}

	isSystem, err := isProcessRunningAsSystem(guiProcess)
	if err != nil {
		fmt.Printf("Error checking if the memdump-gui process is running as SYSTEM: %s\n", err)
		return
	}

	if isSystem {
		fmt.Println("The memdump-gui process is running as SYSTEM")
	} else {
		fmt.Println("The memdump-gui process is NOT running as SYSTEM")
	}
}



func (p *program) Stop(s service.Service) error {
	// Any necessary cleanup before stopping the service
	return nil
}

func main() {
	// Get the current executable path
	_, err := checkAndCreateManifestFile()
	if err != nil {
		log.Fatalf("Failed to check and create manifest file: %v", err)
	}
	
	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("Error getting the current executable path: %s\n", err)
		return
	}

	// Get the directory of the current executable
	execDir := filepath.Dir(execPath)

	// Search for the "memdump-gui.exe" in the same directory as the current executable
	memdumpGUIPath := filepath.Join(execDir, "memdump-gui.exe")

	svcConfig := &service.Config{
		Name:        "Memdump",
		DisplayName: "Memdump Service",
		Description: "A service to run the Memdump program.",
		Executable:  memdumpGUIPath,
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}

	logger, err := s.Logger(nil)
	if err != nil {
		log.Fatal(err)
	}

	err = s.Run()
	if err != nil {
		logger.Error(err)
	}
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
func getSystemToken() (syscall.Token, error) {
	var systemToken syscall.Token

	targetFunc := func() {
		var (
			luid       LUID
			lsaHandle  syscall.Handle
			lsaProcess syscall.Handle
		)

		// Register the logon process with the LSA
		status, _, _ := procLsaRegisterLogonProcessW.Call(
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Memdump"))),
			uintptr(unsafe.Pointer(&lsaHandle)),
			uintptr(unsafe.Pointer(&luid)),
		)
		if status != 0 {
			log.Fatalf("Failed to register logon process with LSA: %x", status)
		}
		defer syscall.CloseHandle(lsaHandle)

		// Connect to the LSA untrusted
		status, _, _ = procLsaConnectUntrusted.Call(uintptr(unsafe.Pointer(&lsaProcess)))
		if status != 0 {
			log.Fatalf("Failed to connect to LSA untrusted: %x", status)
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
			log.Fatalf("Failed to get system token: %x", status)
		}
	}

	runWithPrivileges(targetFunc)
	return systemToken, nil
}
func relaunchWithNTPrivileges(programPath string, systemToken windows.Token) error {
	targetFunc := func() {
		var si windows.StartupInfo
		var pi windows.ProcessInformation

		// Duplicate the system token
		var duplicatedToken windows.Token
		err := windows.DuplicateTokenEx(
			systemToken,
			windows.TOKEN_ALL_ACCESS,
			nil,
			windows.SecurityImpersonation,
			windows.TokenPrimary,
			&duplicatedToken,
		)
		if err != nil {
			log.Fatalf("Failed to duplicate the system token: %s", err)
		}
		defer duplicatedToken.Close()

		// Create the process with the duplicated system token
		err = windows.CreateProcessAsUser(
			duplicatedToken,
			syscall.StringToUTF16Ptr(programPath),
			nil,
			nil,
			nil,
			false,
			windows.CREATE_SUSPENDED,
			nil,
			nil,
			&si,
			&pi,
		)
		if err != nil {
			log.Fatalf("CreateProcessAsUser failed: %s", err)
		}

		// Resume the execution of the new process
		_, err = windows.ResumeThread(pi.Thread)
		if err != nil {
			// Terminate the newly created process if resume fails
			windows.TerminateProcess(pi.Process, 1)
			log.Fatalf("Failed to resume thread: %s", err)
		}

		// Close the process and thread handles
		windows.CloseHandle(pi.Process)
		windows.CloseHandle(pi.Thread)
	}

	runWithPrivileges(targetFunc)

	return nil
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

func enablePrivilege(process windows.Handle, privilegeName string) error {
	var token windows.Token
	err := windows.OpenProcessToken(process, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)

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

func runWithPrivileges(targetFunc func(), process windows.Handle) error {
	// Enable the required privileges
	privileges := []string{
		SE_ASSIGNPRIMARYTOKEN_NAME,
		SE_LOAD_DRIVER_NAME,
		SE_SYSTEM_ENVIRONMENT_NAME,
		SE_TAKE_OWNERSHIP_NAME,
		SE_DEBUG_NAME,
		SE_TCB_NAME,
		SE_SHUTDOWN_PRIVILEGE,
	}

	for _, privilege := range privileges {
		err := enablePrivilege(process, privilege)
		if err != nil {
			log.Fatalf("Failed to enable %s: %v", privilege, err)
		}
	}

	// Run the provided function with the required privileges
	targetFunc()

	return nil
}
