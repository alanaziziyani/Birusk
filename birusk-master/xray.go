package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// معماری:
//   کلاینت --wss--> لبه‌ی Railway (TLS اینجا تموم میشه) --> سرور Go روی PORT
//   --> reverse proxy بر اساس path --> xray-core روی 127.0.0.1 (ws ساده، بدون TLS)
//
// xray-core خودش پروتکل‌های VLESS / Trojan / VMess رو کامل و درست پیاده می‌کنه.

const (
	xrayBinary     = "./xray"
	xrayConfigPath = "xray_config.json"
	xrayAPIPort    = 10085
)

type xrayInbound struct {
	Tag   string
	Proto string
	Path  string
	Port  int
}

// هر پروتکل یک inbound جدا با path ثابت خودش داره
var xrayInbounds = []xrayInbound{
	{Tag: "vless-ws", Proto: "vless", Path: "/vless", Port: 10001},
	{Tag: "trojan-ws", Proto: "trojan", Path: "/trojan", Port: 10002},
	{Tag: "vmess-ws", Proto: "vmess", Path: "/vmess", Port: 10003},
}

type xrayUser struct {
	ID     string `json:"id"`
	Vless  bool   `json:"vless"`
	Trojan bool   `json:"trojan"`
	Vmess  bool   `json:"vmess"`
}

var (
	xrayMu       sync.Mutex
	xrayCmd      *exec.Cmd
	xrayDone     chan struct{}
	xrayLastHash string
	xrayReloadCh = make(chan struct{}, 1)
	xrayProxies  = map[string]*httputil.ReverseProxy{}
)

// ---------------------------------------------------------------------------
// کاربران مجاز: فعال، منقضی‌نشده، و بدون عبور از سقف حجم
// ---------------------------------------------------------------------------

func allowedXrayUsers() []xrayUser {
	rows, err := DB.Query(`SELECT id, COALESCE(expire_time, 0), COALESCE(data_limit, 0),
		COALESCE(vless_enabled, 1), COALESCE(trojan_enabled, 1), COALESCE(vmess_enabled, 1)
		FROM users WHERE status = 'active'`)
	if err != nil {
		log.Printf("[xray] failed to load users: %v", err)
		return nil
	}

	type userRow struct {
		u     xrayUser
		exp   int64
		limit int64
	}
	var all []userRow
	for rows.Next() {
		var id string
		var exp, limit int64
		var v, t, m int
		if err := rows.Scan(&id, &exp, &limit, &v, &t, &m); err != nil {
			continue
		}
		all = append(all, userRow{
			u:     xrayUser{ID: id, Vless: v == 1, Trojan: t == 1, Vmess: m == 1},
			exp:   exp,
			limit: limit,
		})
	}
	rows.Close()

	now := time.Now().Unix()
	var users []xrayUser
	for _, r := range all {
		if r.exp > 0 && now > r.exp {
			continue
		}
		if r.limit > 0 {
			used, _ := GetTotalUsage(r.u.ID)
			if used >= r.limit {
				continue
			}
		}
		users = append(users, r.u)
	}

	sort.Slice(users, func(i, j int) bool { return users[i].ID < users[j].ID })
	return users
}

func usersHash(users []xrayUser) string {
	b, _ := json.Marshal(users)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// ساخت کانفیگ xray
// ---------------------------------------------------------------------------

func buildXrayConfig(users []xrayUser) ([]byte, error) {
	inbounds := []map[string]interface{}{
		{
			"tag":      "api",
			"listen":   "127.0.0.1",
			"port":     xrayAPIPort,
			"protocol": "dokodemo-door",
			"settings": map[string]interface{}{"address": "127.0.0.1"},
		},
	}

	for _, ib := range xrayInbounds {
		var clients []map[string]interface{}

		for _, u := range users {
			switch ib.Proto {
			case "vless":
				if u.Vless {
					clients = append(clients, map[string]interface{}{"id": u.ID, "email": u.ID, "level": 0})
				}
			case "trojan":
				if u.Trojan {
					clients = append(clients, map[string]interface{}{"password": u.ID, "email": u.ID, "level": 0})
				}
			case "vmess":
				if u.Vmess {
					clients = append(clients, map[string]interface{}{"id": u.ID, "email": u.ID, "level": 0})
				}
			}
		}

		// اگه هیچ کاربری نبود، یه کلاینت ساختگی میذاریم تا کانفیگ همیشه معتبر بمونه
		if len(clients) == 0 {
			dummy := uuid.New().String()
			email := "dummy-" + ib.Proto
			if ib.Proto == "trojan" {
				clients = append(clients, map[string]interface{}{"password": dummy, "email": email, "level": 0})
			} else {
				clients = append(clients, map[string]interface{}{"id": dummy, "email": email, "level": 0})
			}
		}

		settings := map[string]interface{}{"clients": clients}
		if ib.Proto == "vless" {
			settings["decryption"] = "none"
		}

		inbounds = append(inbounds, map[string]interface{}{
			"tag":      ib.Tag,
			"listen":   "127.0.0.1",
			"port":     ib.Port,
			"protocol": ib.Proto,
			"settings": settings,
			"streamSettings": map[string]interface{}{
				"network":  "ws",
				"security": "none",
				"wsSettings": map[string]interface{}{
					"path": ib.Path,
				},
			},
		})
	}

	cfg := map[string]interface{}{
		"log":   map[string]interface{}{"loglevel": "warning"},
		"api":   map[string]interface{}{"tag": "api", "services": []string{"StatsService"}},
		"stats": map[string]interface{}{},
		"policy": map[string]interface{}{
			"levels": map[string]interface{}{
				"0": map[string]interface{}{"statsUserUplink": true, "statsUserDownlink": true},
			},
			"system": map[string]interface{}{"statsInboundUplink": true, "statsInboundDownlink": true},
		},
		"inbounds": inbounds,
		"outbounds": []map[string]interface{}{
			{"protocol": "freedom", "tag": "direct"},
			{"protocol": "blackhole", "tag": "blocked"},
		},
		"routing": map[string]interface{}{
			"rules": []map[string]interface{}{
				{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"},
			},
		},
	}

	return json.MarshalIndent(cfg, "", "  ")
}

// ---------------------------------------------------------------------------
// مدیریت پروسه
// ---------------------------------------------------------------------------

func xrayRunning() bool {
	if xrayCmd == nil || xrayDone == nil {
		return false
	}
	select {
	case <-xrayDone:
		return false
	default:
		return true
	}
}

func stopXrayLocked() {
	if xrayCmd != nil && xrayCmd.Process != nil {
		if xrayRunning() {
			xrayCmd.Process.Kill()
		}
		<-xrayDone
	}
	xrayCmd = nil
	xrayDone = nil
}

func applyXray() {
	xrayMu.Lock()
	defer xrayMu.Unlock()

	if _, err := os.Stat(xrayBinary); err != nil {
		log.Printf("[xray] binary %s not found: %v", xrayBinary, err)
		return
	}

	// ریستارت شمارنده‌ها رو صفر می‌کنه، پس اول آخرین مصرف رو ثبت می‌کنیم
	if xrayRunning() {
		pollXrayUsage()
	}

	users := allowedXrayUsers()
	cfgBytes, err := buildXrayConfig(users)
	if err != nil {
		log.Printf("[xray] failed to build config: %v", err)
		return
	}
	if err := os.WriteFile(xrayConfigPath, cfgBytes, 0600); err != nil {
		log.Printf("[xray] failed to write config: %v", err)
		return
	}

	stopXrayLocked()

	cmd := exec.Command(xrayBinary, "run", "-c", xrayConfigPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		log.Printf("[xray] failed to start: %v", err)
		return
	}

	done := make(chan struct{})
	go func() {
		err := cmd.Wait()
		log.Printf("[xray] process exited: %v", err)
		close(done)
	}()

	xrayCmd = cmd
	xrayDone = done
	xrayLastHash = usersHash(users)
	log.Printf("[xray] started with %d active user(s)", len(users))
}

func requestXrayReload() {
	select {
	case xrayReloadCh <- struct{}{}:
	default:
	}
}

// حلقه‌ی اصلی: ریلود با debounce، پایش مصرف، و بازسازی خودکار اگه پروسه مرد
func xrayManager() {
	applyXray()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-xrayReloadCh:
			time.Sleep(1500 * time.Millisecond)
			select {
			case <-xrayReloadCh:
			default:
			}
			applyXray()
		case <-ticker.C:
			xrayTick()
		}
	}
}

func xrayTick() {
	xrayMu.Lock()
	running := xrayRunning()
	if running {
		pollXrayUsage()
	}
	lastHash := xrayLastHash
	xrayMu.Unlock()

	// اگه پروسه مرده، یا لیست کاربران مجاز عوض شده (انقضا / پر شدن حجم)، دوباره بالا میاریم
	if !running || usersHash(allowedXrayUsers()) != lastHash {
		applyXray()
	}
}

// ---------------------------------------------------------------------------
// مصرف واقعی از Stats API خود xray
// ---------------------------------------------------------------------------

func railwayNodeID() string {
	var id string
	err := DB.QueryRow("SELECT id FROM nodes WHERE type = 'railway' AND status = 'active' LIMIT 1").Scan(&id)
	if err != nil {
		return "railway-local"
	}
	return id
}

func statValue(v interface{}) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case string:
		n, _ := strconv.ParseInt(t, 10, 64)
		return n
	}
	return 0
}

func pollXrayUsage() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, xrayBinary, "api", "statsquery",
		fmt.Sprintf("--server=127.0.0.1:%d", xrayAPIPort), "-reset=true").Output()
	if err != nil {
		log.Printf("[xray] statsquery failed: %v", err)
		return
	}

	text := string(out)
	if idx := strings.Index(text, "{"); idx > 0 {
		text = text[idx:]
	}

	var resp struct {
		Stat []struct {
			Name  string      `json:"name"`
			Value interface{} `json:"value"`
		} `json:"stat"`
	}
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		log.Printf("[xray] statsquery parse error: %v", err)
		return
	}

	// نام شمارنده‌ها: user>>>EMAIL>>>traffic>>>uplink|downlink
	perUser := map[string]int64{}
	for _, s := range resp.Stat {
		parts := strings.Split(s.Name, ">>>")
		if len(parts) != 4 || parts[0] != "user" || parts[2] != "traffic" {
			continue
		}
		perUser[parts[1]] += statValue(s.Value)
	}

	nodeID := railwayNodeID()
	for userID, bytes := range perUser {
		if bytes > 0 {
			RecordUsage(userID, nodeID, bytes)
		}
	}
}

// ---------------------------------------------------------------------------
// Reverse proxy: درخواست‌های WebSocket عمومی -> inbound های لوکال xray
// ---------------------------------------------------------------------------

func initXrayProxies() {
	for _, ib := range xrayInbounds {
		target, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", ib.Port))
		if err != nil {
			log.Fatalf("[xray] bad proxy target: %v", err)
		}
		p := httputil.NewSingleHostReverseProxy(target)
		p.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[xray-proxy] %s %s: %v", r.Method, r.URL.Path, err)
			w.WriteHeader(http.StatusBadGateway)
		}
		xrayProxies[ib.Path] = p
	}
}

func xrayProxyFor(path string) *httputil.ReverseProxy {
	for _, ib := range xrayInbounds {
		if path == ib.Path || strings.HasPrefix(path, ib.Path+"/") {
			return xrayProxies[ib.Path]
		}
	}
	return nil
}
