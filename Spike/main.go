package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"unicode"
)

func installService() {
	// Copy binary to /var/opt
	execPath, err := os.Executable()
	if err != nil {
		fmt.Println("Error getting executable path:", err)
		return
	}

	destPath := "/var/opt/spike"
	err = os.MkdirAll("/var/opt", 0755)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}

	input, err := os.ReadFile(execPath)
	if err != nil {
		fmt.Println("Error reading executable:", err)
		return
	}

	err = os.WriteFile(destPath, input, 0755)
	if err != nil {
		fmt.Println("Error copying executable:", err)
		return
	}

	// Create systemd service file
	serviceContent := `[Unit]
Description=Hash Check Service

[Service]
ExecStart=/var/opt/spike --bg true
Type=oneshot`

	err = os.WriteFile("/etc/systemd/system/spike.service", []byte(serviceContent), 0644)
	if err != nil {
		fmt.Println("Error creating service file:", err)
		return
	}

	// Create systemd timer file
	timerContent := `[Unit]
Description=Run Spike every 5 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
Unit=spike.service

[Install]
WantedBy=timers.target`

	err = os.WriteFile("/etc/systemd/system/spike.timer", []byte(timerContent), 0644)
	if err != nil {
		fmt.Println("Error creating timer file:", err)
		return
	}

	// Reload systemd and enable/start timer
	//
	//
	_, err = exec.LookPath("chcon")
	if err == nil {
		exec.Command("chcon", "-R", "-t", "bin_t", "/var/opt/spike").Run()
	}
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "spike.timer").Run()
	exec.Command("systemctl", "start", "spike.timer").Run()
}

func contains(slice []string, str string) bool {
	for _, v := range slice {
		if v == str {
			return true
		}
	}
	return false
}

func paccheckReinstall(reinstall bool) {
	// Check if paccheck is available (part of pacman)
	_, err := exec.LookPath("paccheck")
	if err != nil {
		fmt.Println("Error: paccheck is not available (should be part of pacutils. pacman -Syu pacutils)")
		return
	}

	// Run paccheck and capture output
	fmt.Println("Running paccheck...")
	paccheckOutput, err := exec.Command("paccheck", "--md5sum", "--quiet").Output()
	if err != nil {
		fmt.Println("Error running paccheck:", err)
	}

	// Parse output and extract package names
	lines := strings.Split(string(paccheckOutput), "\n")
	packages := make(map[string]struct{}) // Using map as a set for unique packages

	for _, line := range lines {
		if line == "" {
			continue
		}

		// paccheck output format: "package: file md5sum mismatch"
		parts := strings.Split(line, ":")
		if len(parts) >= 1 {
			packageName := strings.TrimSpace(parts[0])
			packages[packageName] = struct{}{}
		}
	}

	// Convert map to slice for display
	var packageList []string
	for pkg := range packages {
		packageList = append(packageList, pkg)
	}

	fmt.Printf("\nPackages to be reinstalled:\n")
	for _, pkg := range packageList {
		fmt.Printf("- %s\n", pkg)
	}

	if reinstall && len(packages) > 0 {
		fmt.Printf("\nReady to reinstall %d packages. Continue? (y/N): ", len(packageList))
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) == "y" {
			for _, pkg := range packageList {
				cmd := exec.Command("pacman", "-S", "--noconfirm", pkg)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err != nil {
					fmt.Printf("Error reinstalling %s: %v\n", pkg, err)
				}
			}
		} else {
			fmt.Println("Reinstallation cancelled.")
		}
	}
}

func rpmVerifyReinstall(reinstall bool) {
	// Check if rpm is installed
	_, err := exec.LookPath("rpm")
	if err != nil {
		fmt.Println("Error: rpm is not installed")
		return
	}

	// Run rpm -Va and capture output
	fmt.Println("Running rpm verification...")
	rpmOutput, err := exec.Command("rpm", "-Va").Output()
	if err != nil {
		fmt.Println("Error running rpm -Va:", err)
		//return
	}
	// Split output into lines and extract package names
	lines := strings.Split(string(rpmOutput), "\n")
	var packages []string
	for _, line := range lines {
		if line == "" {
			continue
		}
		// RPM verification output format: "S.5....T.  c /path/to/file"
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			// Skip config files (those with 'c' in the second field)
			if len(fields) >= 2 && strings.Contains(fields[1], "c") {
				continue
			}

			// Get package name for the file
			queryOutput, err := exec.Command("rpm", "-qf", fields[len(fields)-1]).Output()
			if err != nil {
				fmt.Printf("Error getting package name for %s: %v\n", fields[len(fields)-1], err)
				continue
			}

			packageName := strings.TrimSpace(string(queryOutput))
			// Add unique package names
			if !contains(packages, packageName) {
				packages = append(packages, packageName)
			}
		}
	}

	fmt.Printf("\nPackages to be reinstalled:\n")
	for _, pkg := range packages {
		fmt.Printf("- %s\n", pkg)
	}
	if reinstall && len(packages) > 0 {
		fmt.Printf("\nReady to reinstall %d packages. Continue? (y/N): ", len(packages))
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) == "y" {
			for _, pkg := range packages {
				cmd := exec.Command("dnf", "reinstall", "-y", pkg)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err != nil {
					fmt.Printf("Error reinstalling %s: %v\n", pkg, err)
				}
			}
		} else {
			fmt.Println("Reinstallation cancelled.")
		}
	}
}

// detectPackageManager attempts to detect the package manager based on available commands
func detectPackageManager() string {
	// List of common Linux package managers
	packageManagers := []string{"apt", "rpm", "dnf", "pacman", "apk"}

	for _, manager := range packageManagers {
		if _, err := exec.LookPath(manager); err == nil {
			return manager
		}
	}

	return "unknown"
}

func aptDebsumsReinstall(reinstall bool) {
	// Check if debsums is installed
	_, err := exec.LookPath("debsums")
	if err != nil {
		// Install debsums if not found
		fmt.Println("Installing debsums...")
		cmd := exec.Command("apt", "install", "-y", "debsums")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Println("Error installing debsums:", err)
			return
		}
	}

	// Run debsums and capture output
	fmt.Println("Running debsums...")
	debsumsOutput, err := exec.Command("debsums", "-c").Output()
	if err != nil {
		fmt.Println("Error running debsums:", err)
		//return
	}

	// Split output into lines and run dpkg -S for each file
	files := strings.Split(string(debsumsOutput), "\n")
	var packages []string
	for _, file := range files {
		if file == "" {
			continue
		}
		dpkgOutput, err := exec.Command("dpkg", "-S", file).Output()
		if err != nil {
			fmt.Printf("Error running dpkg -S for %s: %v\n", file, err)
			continue
		}

		// Extract package name before the colon
		parts := strings.Split(string(dpkgOutput), ":")
		if len(parts) > 0 {
			packageName := strings.TrimSpace(parts[0])
			// Add unique package names to a set
			packages = append(packages, packageName)
		}

	}
	fmt.Printf("\nPackages to be reinstalled:\n")
	for _, pkg := range packages {
		fmt.Printf("- %s\n", pkg)
	}
	if reinstall {
		fmt.Printf("\nReady to reinstall %d packages. Continue? (y/N): ", len(packages))
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) == "y" {

			for _, value := range packages {
				output, err := exec.Command("apt", "reinstall", "-y", value).Output()
				if err != nil {
					fmt.Printf("Error running apt %v, %s\n", err, output)
					continue
				}

			}
		} else {
			fmt.Println("Reinstallation cancelled.")
		}
	}
}

func procCheck() {
	files, err := os.ReadDir("/proc")
	fmt.Printf("\nCheck proc\n")
	if err != nil {
		fmt.Println("Error reading /proc:", err)
		return
	}

	for _, file := range files {
		// Check if the directory name is a number (PID)
		if pid := file.Name(); strings.IndexFunc(pid, func(c rune) bool {
			return !unicode.IsDigit(c)
		}) == -1 {
			exePath := fmt.Sprintf("/proc/%s/exe", pid)

			realPath, err := os.Readlink(exePath)
			if err != nil {
				continue
			}

			// Get hash of file on disk
			diskFile, err := os.Open(realPath)
			if err != nil {
				fmt.Printf("On disk file not found: %s\n", realPath)
				continue
			}
			defer diskFile.Close()

			// Calculate SHA256 hash
			h := sha256.New()
			if _, err := io.Copy(h, diskFile); err != nil {
				fmt.Printf("Error calculating hash for %s: %v\n", realPath, err)
				continue
			}
			currentHash := fmt.Sprintf("%x", h.Sum(nil))

			// Read previous hash from file
			os.MkdirAll("/var/cache/spike/", 0755)
			hashFile := fmt.Sprintf("/var/cache/spike/%x.hash", sha256.Sum256([]byte(realPath)))

			previousHash, err := os.ReadFile(hashFile)
			if err != nil {
				// Save initial hash if file doesn't exist
				err = os.WriteFile(hashFile, []byte(currentHash), 0644)
				if err != nil {
					fmt.Printf("Error saving hash for %s: %v\n", realPath, err)
				}
				continue
			}

			// Compare hashes
			if string(previousHash) != currentHash {
				fmt.Printf("WARNING: Hash mismatch for %s\n", realPath)
				fmt.Printf("Previous: %s\n", string(previousHash))
				fmt.Printf("Current:  %s\n", currentHash)

				// Update stored hash
				err = os.WriteFile(hashFile, []byte(currentHash), 0644)
				if err != nil {
					fmt.Printf("Error updating hash for %s: %v\n", realPath, err)
				}
			}
		}
	}
}

func main() {
	var install = flag.Bool("install", false, "help message for flag n")
	var bg = flag.Bool("bg", false, "help message for flag n")
	flag.Parse()
	if *install {
		installService()
		return
	}
	packageManager := detectPackageManager()
	procCheck()
	if packageManager == "unknown" {
		fmt.Println("No known package manager detected.")
	} else {
		fmt.Printf("Detected package manager: %s\n", packageManager)
	}
	switch packageManager {
	case "apt":
		aptDebsumsReinstall(!*bg)
	case "rpm":
		rpmVerifyReinstall(!*bg)
	case "pacman":
		paccheckReinstall(!*bg)
	}

}
