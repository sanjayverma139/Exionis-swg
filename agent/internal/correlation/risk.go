package correlation

import "strings"

func computeRiskScore(evt StructuredEvent, cmdline string) (int, []string) {
	score := 0
	reasons := []string{}

	image := strings.ToLower(evt.Image)

	lolbins := map[string]int{
		"powershell.exe": 15, "pwsh.exe": 15,
		"certutil.exe": 20, "bitsadmin.exe": 20,
		"mshta.exe": 25, "rundll32.exe": 15,
		"regsvr32.exe": 20, "wmic.exe": 15,
		"scrcons.exe": 30, "installutil.exe": 20,
	}
	if pts, ok := lolbins[image]; ok {
		score += pts
		reasons = append(reasons, "lolbin_usage")
	}

	cmdLower := strings.ToLower(cmdline)
	if strings.Contains(cmdLower, "-enc") || strings.Contains(cmdLower, "-encodedcommand") {
		score += 40
		reasons = append(reasons, "encoded_command")
	}
	if strings.Contains(cmdLower, "frombase64") || strings.Contains(cmdLower, "iex(") || strings.Contains(cmdLower, "invoke-expression") {
		score += 35
		reasons = append(reasons, "dynamic_execution")
	}
	if strings.Contains(cmdLower, "-windowstyle hidden") || strings.Contains(cmdLower, "-nop -w hidden") {
		score += 25
		reasons = append(reasons, "hidden_window")
	}

	if evt.ParentImage != "" {
		parent := strings.ToLower(evt.ParentImage)
		if (parent == "winword.exe" || parent == "excel.exe" || parent == "powerpnt.exe") && image == "cmd.exe" {
			score += 35
			reasons = append(reasons, "office_spawn_cmd")
		}
		if parent == "cmd.exe" && (image == "powershell.exe" || image == "pwsh.exe") {
			score += 20
			reasons = append(reasons, "cmd_spawn_powershell")
		}
		if parent == "explorer.exe" && (image == "cmd.exe" || image == "powershell.exe") && evt.Depth >= 2 {
			score += 15
			reasons = append(reasons, "deep_shell_spawn")
		}
	}

	if evt.ImagePath != "" {
		pathLower := strings.ToLower(evt.ImagePath)
		if strings.Contains(pathLower, `\temp\`) || strings.Contains(pathLower, `\appdata\local\temp\`) {
			score += 25
			reasons = append(reasons, "temp_folder_execution")
		}
		if strings.Contains(pathLower, `\users\public\`) {
			score += 20
			reasons = append(reasons, "public_folder_execution")
		}
	}

	if score > 100 {
		score = 100
	}

	return score, reasons
}
