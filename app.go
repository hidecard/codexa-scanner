package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type App struct {
	ctx        context.Context
	scanCancel context.CancelFunc
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// ==========================================
// 1. REAL-TIME PORT SCANNER + BANNER GRABBER
// ==========================================

type PortFinding struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Banner  string `json:"banner"`
}

var commonPorts = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
	80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
	3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
	8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

func grabBanner(conn net.Conn, target string, port int) string {
	conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))

	// HTTP/HTTPS port ဖြစ်နေရင် HEAD request လှမ်းပို့ပြီး Server header ယူမယ်
	if port == 80 || port == 8080 || port == 8000 {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", target)
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}

	raw := string(buf[:n])
	// HTTP response ဖြစ်ရင် Server header ကိုပဲ သန့်သန့်လေး ဆွဲထုတ်မယ်
	if strings.HasPrefix(raw, "HTTP/") {
		for _, line := range strings.Split(raw, "\r\n") {
			if strings.HasPrefix(strings.ToLower(line), "server:") {
				return strings.TrimSpace(line)
			}
		}
		return strings.Split(raw, "\r\n")[0]
	}

	// တခြား Banner တွေ (SSH, FTP, SMTP) အတွက် ပထမဆုံးစာကြောင်းကို ယူမယ်
	clean := strings.TrimSpace(strings.Split(raw, "\n")[0])
	if len(clean) > 80 {
		clean = clean[:80] + "..."
	}
	return clean
}

func (a *App) StartPortScan(target string, startPort, endPort, workers, timeoutMs int) string {
	if target == "" {
		return "Target is required"
	}
	if startPort < 1 || endPort > 65535 || startPort > endPort {
		return "Invalid port range (1-65535)"
	}
	if workers <= 0 {
		workers = 150
	}
	if timeoutMs <= 0 {
		timeoutMs = 800
	}

	// အရင် Scan run နေတာရှိရင် အရင်ရပ်မယ်
	if a.scanCancel != nil {
		a.scanCancel()
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.scanCancel = cancel

	totalPorts := endPort - startPort + 1
	var scannedCount int64

	go func() {
		defer cancel()
		ports := make(chan int, workers)
		var wg sync.WaitGroup
		timeout := time.Duration(timeoutMs) * time.Millisecond

		// Worker Pool စတင်ခြင်း
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for p := range ports {
					select {
					case <-ctx.Done():
						return
					default:
						address := fmt.Sprintf("%s:%d", target, p)
						conn, err := net.DialTimeout("tcp", address, timeout)
						if err == nil {
							banner := grabBanner(conn, target, p)
							conn.Close()

							svc := commonPorts[p]
							if svc == "" {
								svc = "unknown"
							}

							// Open port တွေ့တာနဲ့ Frontend ဆီ Real-time ပို့မယ်
							runtime.EventsEmit(a.ctx, "port:found", PortFinding{
								Port:    p,
								Service: svc,
								Banner:  banner,
							})
						}

						curr := atomic.AddInt64(&scannedCount, 1)
						// UI ကိုဝန်မပိစေဖို့ port 25 ခုတစ်ခါ Progress update ပို့မယ်
						if curr%25 == 0 || int(curr) == totalPorts {
							pct := int((float64(curr) / float64(totalPorts)) * 100)
							runtime.EventsEmit(a.ctx, "scan:progress", pct)
						}
					}
				}
			}()
		}

		// Ports တွေကို Channel ထဲ ထည့်ခြင်း
	Loop:
		for p := startPort; p <= endPort; p++ {
			select {
			case <-ctx.Done():
				break Loop
			case ports <- p:
			}
		}
		close(ports)
		wg.Wait()

		runtime.EventsEmit(a.ctx, "scan:done", true)
	}()

	return "STARTED"
}

func (a *App) StopPortScan() {
	if a.scanCancel != nil {
		a.scanCancel()
	}
}

// ==========================================
// 2. BULK HTTP SECURITY & TECH ANALYZER
// ==========================================

type BulkHeaderResult struct {
	URL        string            `json:"url"`
	StatusCode int               `json:"statusCode"`
	Title      string            `json:"title"`
	Server     string            `json:"server"`
	PoweredBy  string            `json:"poweredBy"`
	Grade      string            `json:"grade"`
	Missing    []string          `json:"missing"`
	Present    map[string]string `json:"present"`
	Error      string            `json:"error"`
}

var titleRegex = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)

func (a *App) AnalyzeBulkURLs(rawInput string, concurrency int) []BulkHeaderResult {
	var urls []string
	scanner := bufio.NewScanner(strings.NewReader(rawInput))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}

	if len(urls) == 0 {
		return nil
	}
	if concurrency <= 0 {
		concurrency = 10
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 10 * time.Second,
	}

	secHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Permissions-Policy",
	}

	results := make([]BulkHeaderResult, len(urls))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for idx, rawURL := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, target string) {
			defer wg.Done()
			defer func() { <-sem }()

			if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
				target = "https://" + target
			}

			req, err := http.NewRequest("GET", target, nil)
			if err != nil {
				results[i] = BulkHeaderResult{URL: target, Error: err.Error()}
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetRecon/2.0")

			resp, err := client.Do(req)
			if err != nil {
				results[i] = BulkHeaderResult{URL: target, Error: "Connection failed / Timeout"}
				return
			}
			defer resp.Body.Close()

			// HTML Title ဆွဲထုတ်ရန် Body အစပိုင်း 32KB လောက်ပဲ ဖတ်မယ် (Memory သက်သာအောင်)
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
			title := ""
			if matches := titleRegex.FindStringSubmatch(string(bodyBytes)); len(matches) > 1 {
				title = strings.TrimSpace(matches[1])
			}

			var missing []string
			present := make(map[string]string)

			for _, h := range secHeaders {
				val := resp.Header.Get(h)
				if val == "" {
					missing = append(missing, h)
				} else {
					present[h] = val
				}
			}

			// Security Grade တွက်ချက်ခြင်း
			grade := "A"
			switch len(missing) {
			case 0:
				grade = "A+"
			case 1, 2:
				grade = "B"
			case 3, 4:
				grade = "C"
			default:
				grade = "F"
			}

			results[i] = BulkHeaderResult{
				URL:        target,
				StatusCode: resp.StatusCode,
				Title:      title,
				Server:     resp.Header.Get("Server"),
				PoweredBy:  resp.Header.Get("X-Powered-By"),
				Grade:      grade,
				Missing:    missing,
				Present:    present,
			}
		}(idx, rawURL)
	}

	wg.Wait()
	return results
}

// ==========================================
// 3. NATIVE EXPORT (JSON & CSV)
// ==========================================

func (a *App) ExportJSON(defaultFilename string, jsonData string) (string, error) {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Save Scan Report (JSON)",
		DefaultFilename: defaultFilename,
		Filters: []runtime.FileFilter{
			{DisplayName: "JSON Files (*.json)", Pattern: "*.json"},
		},
	})
	if err != nil || path == "" {
		return "", err
	}

	// Pretty print JSON
	var raw interface{}
	if err := json.Unmarshal([]byte(jsonData), &raw); err == nil {
		if pretty, err := json.MarshalIndent(raw, "", "  "); err == nil {
			jsonData = string(pretty)
		}
	}

	err = os.WriteFile(path, []byte(jsonData), 0644)
	return path, err
}

func (a *App) ExportPortsCSV(findings []PortFinding) (string, error) {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Save Port Scan Report (CSV)",
		DefaultFilename: "port_scan_report.csv",
		Filters: []runtime.FileFilter{
			{DisplayName: "CSV Files (*.csv)", Pattern: "*.csv"},
		},
	})
	if err != nil || path == "" {
		return "", err
	}

	file, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Port", "Protocol", "Service", "Banner"})
	for _, f := range findings {
		writer.Write([]string{strconv.Itoa(f.Port), "TCP", f.Service, f.Banner})
	}

	return path, nil
}

