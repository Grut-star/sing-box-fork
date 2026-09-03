package eidolon

import (
	"log"
	"os/exec"
	"runtime"
)

// OptimizeSysctls автоматически настраивает TCP BBR, FQ и буферы BDP
func OptimizeSysctls() {
	if runtime.GOOS != "linux" {
		log.Println("Skipping sysctl optimization: not a Linux system.")
		return
	}

	params := map[string]string{
		"net.core.default_qdisc":            "fq",        // Планировщик FQ для BBR
		"net.ipv4.tcp_congestion_control":   "bbr",       // Активация BBR
		"net.ipv4.tcp_slow_start_after_idle": "0",        // Убираем сброс окна после простоя
		"net.ipv4.tcp_notsent_lowat":        "16384",     // Ограничение неотправленных буферов для HTTP/2
		"net.core.rmem_max":                 "67108864",  // 64 MiB Buffer High-Watermark (Downlink)
		"net.core.wmem_max":                 "67108864",  // 64 MiB Buffer High-Watermark (Uplink)
	}

	for key, val := range params {
		cmd := exec.Command("sysctl", "-w", key+"="+val)
		if err := cmd.Run(); err != nil {
			log.Printf("[!] Failed to set kernel parameter %s = %s: %v (Ensure root privileges)", key, val, err)
		} else {
			log.Printf("[+] Kernel tuned: %s = %s", key, val)
		}
	}
}