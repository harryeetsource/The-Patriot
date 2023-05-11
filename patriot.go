package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/kardianos/service"

	"golang.org/x/sys/windows"
)

const (
	PROCESS_ALL_ACCESS         = 0x1F0FFF
	MEM_COMMIT                 = 0x1000
	SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege"
	SE_LOAD_DRIVER_NAME        = "SeLoadDriverPrivilege"
	SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege"
	SE_TAKE_OWNERSHIP_NAME     = "SeTakeOwnershipPrivilege"
)

type patriotService struct {
	Service service.Service
}

func (s *patriotService) Start(service.Service) error {
	go s.run()
	return nil
}

func (s *patriotService) Stop(service.Service) error {
	// Here, you can add any cleanup code or stop any long-running operations
	return nil
}

func (s *patriotService) run() {
	// Call your existing runPatriot function here
	runPatriot()
}
func runWithPrivileges(targetFunc func()) {
	// Enable the required privileges
	privileges := []string{
		SE_ASSIGNPRIMARYTOKEN_NAME,
		SE_LOAD_DRIVER_NAME,
		SE_SYSTEM_ENVIRONMENT_NAME,
		SE_TAKE_OWNERSHIP_NAME,
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
func runPatriot() {
	fmt.Println("Ensuring adequate privileges")
	runWithPrivileges(func() {
		startGUI()
	})
}

func startGUI() {
	// Get the path of the current running process
	runningPath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}

	// Print the path of the running executable
	fmt.Println("Executable path:", runningPath)

	// Print the current working directory
	wd, _ := os.Getwd()
	fmt.Println("Working directory:", wd)

	// Get the directory containing the executable
	exeDir := filepath.Dir(runningPath)

	// Construct the path to patriot-gui.exe
	patriotGUIPath := filepath.Join(exeDir, "patriot-gui.exe")
	// Print the path to patriot-gui.exe
	fmt.Println("Patriot-GUI path:", patriotGUIPath)
	// Run patriot-gui.exe
	cmd := exec.Command(patriotGUIPath)
	err = cmd.Run()
	if err != nil {
		log.Printf("Failed to start GUI: %v", err)
	}
}

func main() {
	svcConfig := &service.Config{
		Name:        "PatriotService",
		DisplayName: "The Patriot Service",
		Description: "This is The Patriot Service.",
	}

	p := &patriotService{}
	s, err := service.New(p, svcConfig)
	if err != nil {
		log.Fatal(err)
	}
	p.Service = s

	logger, err := s.Logger(nil)
	if err != nil {
		log.Fatal(err)
	}

	if len(os.Args) > 1 {
		err := service.Control(s, os.Args[1])
		if err != nil {
			log.Printf("Valid actions: %q\n", service.ControlAction)
			log.Fatal(err)
		}
		return
	}

	err = s.Run()
	if err != nil {
		logger.Error(err)
	}
}
