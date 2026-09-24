package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

type User struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Status        string `json:"status"`
	DataLimit     int64  `json:"data_limit"`
	ExpireTime    int64  `json:"expire_time"`
	VlessEnabled  int    `json:"vless_enabled"`
	TrojanEnabled int    `json:"trojan_enabled"`
	VmessEnabled  int    `json:"vmess_enabled"`
	CustomRemark  string `json:"custom_remark"`
	UsedData      int64  `json:"used_data"`
}

type Node struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Address     string `json:"address"`
	CleanIP     string `json:"clean_ip"`
	Port        int    `json:"port"`
	Transport   string `json:"transport"`
	Security    string `json:"security"`
	Path        string `json:"path"`
	Host        string `json:"host"`
	Pbk         string `json:"pbk"`
	Sid         string `json:"sid"`
	Flow        string `json:"flow"`
	Fingerprint string `json:"fingerprint"`
	Token       string `json:"token"`
	Status      string `json:"status"`
}

type AppSettings struct {
	SubDomain      string `json:"subDomain"`
	DefaultCleanIp string `json:"defaultCleanIp"`
	EnableStats    bool   `json:"enableStats"`
	MtprotoEnabled bool   `json:"mtprotoEnabled"`
	MtprotoPort    string `json:"mtprotoPort"`
	MtprotoSecret  string `json:"mtprotoSecret"`
	MtprotoTag     string `json:"mtprotoTag"`
}

type VMessConfig struct {
	V    string `json:"v"`
	Ps   string `json:"ps"`
	Add  string `json:"add"`
	Port string `json:"port"`
	Id   string `json:"id"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	Tls  string `json:"tls"`
	Sni  string `json:"sni"`
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

var (
	mtprotoProcess *exec.Cmd
	mtprotoMutex   sync.Mutex
)

func generateToken() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func cleanDomain(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimPrefix(addr, "https://")
	addr = strings.TrimPrefix(addr, "http://")
	if idx := strings.Index(addr, "/"); idx != -1 {
		addr = addr[:idx]
	}
	return addr
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	InitDB("birusk.db")

	initialSettings := loadSettingsFromDB()
	go applyMtprotoEngine(initialSettings)

	mux := http.NewServeMux()

	fs := http.FileServer(http.Dir("./ui"))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
			handleProxy(w, r)
			return
		}
		fs.ServeHTTP(w, r)
	})

	mux.HandleFunc("GET /api/users", handleGetUsers)
	mux.HandleFunc("POST /api/users", handleCreateUser)
	mux.HandleFunc("DELETE /api/users", handleDeleteUser)
	mux.HandleFunc("PUT /api/users", handleEditUser)

	mux.HandleFunc("GET /api/nodes", handleGetNodes)
	mux.HandleFunc("POST /api/nodes", handleCreateNode)
	mux.HandleFunc("DELETE /api/nodes", handleDeleteNode)
	mux.HandleFunc("PUT /api/nodes", handleEditNode)

	mux.HandleFunc("GET /api/settings", handleGetSettings)
	mux.HandleFunc("POST /api/settings", handleSaveSettings)

	mux.HandleFunc("GET /api/sync", handleNodeSync)
	mux.HandleFunc("POST /api/usage", handleReportUsage)
	mux.HandleFunc("GET /sub", handleSubscription) 

	log.Printf("AlanCoreNet Master Engine running on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[proxy] upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	_, firstChunk, err := conn.ReadMessage()
	if err != nil {
		log.Printf("[proxy] failed to read first message: %v", err)
		return
	}
	if len(firstChunk) < 24 || firstChunk[0] != 0 {
		log.Printf("[proxy] bad header: len=%d version=%d", len(firstChunk), firstChunk[0])
		return
	}

	uuidBytes := firstChunk[1:17]
	parsedUUID, err := uuid.FromBytes(uuidBytes)
	if err != nil {
		log.Printf("[proxy] invalid uuid bytes: %v", err)
		return
	}
	userID := parsedUUID.String()

	var status string
	var expireTime int64
	err = DB.QueryRow("SELECT status, expire_time FROM users WHERE id = ?", userID).Scan(&status, &expireTime)
	if err != nil {
		log.Printf("[proxy] user %s not found: %v", userID, err)
		return
	}
	if status != "active" {
		log.Printf("[proxy] user %s not active (status=%s)", userID, status)
		return
	}
	if expireTime > 0 && time.Now().Unix() > expireTime {
		log.Printf("[proxy] user %s expired", userID)
		return
	}

	var nodeID string
	DB.QueryRow("SELECT id FROM nodes WHERE type = 'railway' AND status = 'active' LIMIT 1").Scan(&nodeID)

	optLen := int(firstChunk[17])
	pPos := 18 + optLen + 1
	if len(firstChunk) <= pPos+2 {
		log.Printf("[proxy] header too short for port/address (optLen=%d)", optLen)
		return
	}
	port := binary.BigEndian.Uint16(firstChunk[pPos : pPos+2])
	aType := firstChunk[pPos+2]

	var targetAddr string
	vPos := pPos + 3
	aLen := 0

	if vPos >= len(firstChunk) {
		log.Printf("[proxy] header too short for address type %d", aType)
		return
	}

	if aType == 1 {
		aLen = 4
		if vPos+aLen > len(firstChunk) {
			log.Printf("[proxy] truncated ipv4 address")
			return
		}
		targetAddr = net.IP(firstChunk[vPos : vPos+aLen]).String()
	} else if aType == 2 {
		aLen = int(firstChunk[vPos])
		vPos++
		if vPos+aLen > len(firstChunk) {
			log.Printf("[proxy] truncated domain address")
			return
		}
		targetAddr = string(firstChunk[vPos : vPos+aLen])
	} else if aType == 3 {
		aLen = 16
		if vPos+aLen > len(firstChunk) {
			log.Printf("[proxy] truncated ipv6 address")
			return
		}
		targetAddr = net.IP(firstChunk[vPos : vPos+aLen]).String()
	} else {
		log.Printf("[proxy] unknown address type %d", aType)
		return
	}

	target := fmt.Sprintf("%s:%d", targetAddr, port)
	targetConn, err := net.DialTimeout("tcp", target, 8*time.Second)
	if err != nil {
		log.Printf("[proxy] dial %s failed: %v", target, err)
		return
	}
	defer targetConn.Close()
	log.Printf("[proxy] user %s connected -> %s", userID, target)

	var writeMu sync.Mutex
	writeMsg := func(messageType int, data []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteMessage(messageType, data)
	}

	writeMsg(websocket.BinaryMessage, []byte{0, 0})

	// پینگ دوره‌ای تا اگه پشت این سرور یه پراکسی/لودبالانسر (مثل خودِ لبه‌ی Railway)
	// کانکشن‌های ساکت رو بعد از یه مدت idle می‌بنده، این کانکشن رو زنده نگه داره.
	pingStop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := writeMsg(websocket.PingMessage, nil); err != nil {
					return
				}
			case <-pingStop:
				return
			}
		}
	}()
	defer close(pingStop)

	var tx, rx int64
	offset := vPos + aLen
	if offset < len(firstChunk) {
		targetConn.Write(firstChunk[offset:])
		atomic.AddInt64(&tx, int64(len(firstChunk)-offset))
	}

	go func() {
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				log.Printf("[proxy] user %s client read ended: %v", userID, err)
				break
			}
			targetConn.Write(msg)
			atomic.AddInt64(&tx, int64(len(msg)))
		}
		targetConn.Close()
	}()

	buf := make([]byte, 32*1024)
	for {
		n, err := targetConn.Read(buf)
		if n > 0 {
			if err2 := writeMsg(websocket.BinaryMessage, buf[:n]); err2 != nil {
				log.Printf("[proxy] user %s write to client failed: %v", userID, err2)
				break
			}
			atomic.AddInt64(&rx, int64(n))
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[proxy] user %s target read ended: %v", userID, err)
			}
			break
		}
	}

	totalUsage := atomic.LoadInt64(&tx) + atomic.LoadInt64(&rx)
	log.Printf("[proxy] user %s session ended -> %s (tx=%d rx=%d)", userID, target, atomic.LoadInt64(&tx), atomic.LoadInt64(&rx))
	if totalUsage > 0 && nodeID != "" {
		RecordUsage(userID, nodeID, totalUsage)
	}
}

func loadSettingsFromDB() AppSettings {
	var s AppSettings
	rows, err := DB.Query("SELECT key, value FROM settings")
	if err != nil {
		return s
	}
	defer rows.Close()

	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		switch k {
		case "sub_domain":
			s.SubDomain = v
		case "default_clean_ip":
			s.DefaultCleanIp = v
		case "enable_stats":
			s.EnableStats = (v == "1" || v == "true")
		case "mtproto_enabled":
			s.MtprotoEnabled = (v == "1" || v == "true")
		case "mtproto_port":
			s.MtprotoPort = v
		case "mtproto_secret":
			s.MtprotoSecret = v
		case "mtproto_tag":
			s.MtprotoTag = v
		}
	}
	return s
}

func handleGetSettings(w http.ResponseWriter, r *http.Request) {
	settings := loadSettingsFromDB()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

func handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	var s AppSettings
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	saveParam("sub_domain", s.SubDomain)
	saveParam("default_clean_ip", s.DefaultCleanIp)
	saveParam("mtproto_port", s.MtprotoPort)
	saveParam("mtproto_secret", s.MtprotoSecret)
	saveParam("mtproto_tag", s.MtprotoTag)

	if s.EnableStats {
		saveParam("enable_stats", "1")
	} else {
		saveParam("enable_stats", "0")
	}

	if s.MtprotoEnabled {
		saveParam("mtproto_enabled", "1")
	} else {
		saveParam("mtproto_enabled", "0")
	}

	go applyMtprotoEngine(s)

	w.WriteHeader(http.StatusOK)
}

func saveParam(key, value string) {
	DB.Exec("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?", key, value, value)
}

func ensureMTGCore() error {
	if _, err := os.Stat("mtg_core"); err == nil {
		return nil
	}
	log.Println("MTProto Engine: Downloading core binary from GitHub...")
	
	resp, err := http.Get("https://github.com/9seconds/mtg/releases/download/v1.0.11/mtg-1.0.11-linux-amd64.tar.gz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		
		if strings.HasSuffix(header.Name, "mtg") && !header.FileInfo().IsDir() {
			f, err := os.OpenFile("mtg_core", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0755)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, tr)
			f.Close()
			if err != nil {
				return err
			}
			log.Println("MTProto Engine: Core downloaded and installed successfully.")
			return nil
		}
	}
	return fmt.Errorf("executable not found in archive")
}

func applyMtprotoEngine(s AppSettings) {
	mtprotoMutex.Lock()
	defer mtprotoMutex.Unlock()

	if mtprotoProcess != nil && mtprotoProcess.Process != nil {
		mtprotoProcess.Process.Kill()
		mtprotoProcess.Wait()
		mtprotoProcess = nil
		log.Println("MTProto Engine: Stopped previous instance.")
	}

	if !s.MtprotoEnabled || s.MtprotoPort == "" || s.MtprotoSecret == "" {
		return
	}

	err := ensureMTGCore()
	if err != nil {
		log.Println("MTProto Engine Error: Could not setup core:", err)
		return
	}

	args := []string{"run", "-b", "0.0.0.0:" + s.MtprotoPort}
	secretToPass := s.MtprotoSecret
	if len(secretToPass) == 32 {
		fakeDomainHex := hex.EncodeToString([]byte("google.com"))
		secretToPass = "ee" + secretToPass + fakeDomainHex
	}
	args = append(args, secretToPass)

	cmd := exec.Command("./mtg_core", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		log.Println("MTProto Engine Error: Failed to start:", err)
		return
	}
	
	mtprotoProcess = cmd
	log.Println("MTProto Engine: Sub-process operational on port", s.MtprotoPort, "with FakeTLS enabled.")
}

func handleGetUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := DB.Query("SELECT id, name, status, data_limit, expire_time, vless_enabled, trojan_enabled, vmess_enabled, custom_remark FROM users")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var userList []User
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Name, &u.Status, &u.DataLimit, &u.ExpireTime, &u.VlessEnabled, &u.TrojanEnabled, &u.VmessEnabled, &u.CustomRemark)
		usage, _ := GetTotalUsage(u.ID)
		u.UsedData = usage
		userList = append(userList, u)
	}

	if userList == nil {
		userList = []User{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userList)
}

func handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string `json:"name"`
		DataLimit     int64  `json:"data_limit"`
		ExpireTime    int64  `json:"expire_time"`
		VlessEnabled  bool   `json:"vless_enabled"`
		TrojanEnabled bool   `json:"trojan_enabled"`
		VmessEnabled  bool   `json:"vmess_enabled"`
		CustomRemark  string `json:"custom_remark"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	vlessVal, trojanVal, vmessVal := 0, 0, 0
	if req.VlessEnabled { vlessVal = 1 }
	if req.TrojanEnabled { trojanVal = 1 }
	if req.VmessEnabled { vmessVal = 1 }

	newID := uuid.New().String()
	_, err := DB.Exec("INSERT INTO users (id, name, data_limit, expire_time, vless_enabled, trojan_enabled, vmess_enabled, custom_remark) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		newID, req.Name, req.DataLimit, req.ExpireTime, vlessVal, trojanVal, vmessVal, req.CustomRemark)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	DB.Exec("DELETE FROM node_usage WHERE user_id = ?", id)
	DB.Exec("DELETE FROM users WHERE id = ?", id)
	w.WriteHeader(http.StatusOK)
}

func handleEditUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		DataLimit     int64  `json:"data_limit"`
		ExpireTime    int64  `json:"expire_time"`
		VlessEnabled  bool   `json:"vless_enabled"`
		TrojanEnabled bool   `json:"trojan_enabled"`
		VmessEnabled  bool   `json:"vmess_enabled"`
		CustomRemark  string `json:"custom_remark"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	vlessVal, trojanVal, vmessVal := 0, 0, 0
	if req.VlessEnabled { vlessVal = 1 }
	if req.TrojanEnabled { trojanVal = 1 }
	if req.VmessEnabled { vmessVal = 1 }

	_, err := DB.Exec("UPDATE users SET name = ?, data_limit = ?, expire_time = ?, vless_enabled = ?, trojan_enabled = ?, vmess_enabled = ?, custom_remark = ? WHERE id = ?",
		req.Name, req.DataLimit, req.ExpireTime, vlessVal, trojanVal, vmessVal, req.CustomRemark, req.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func handleGetNodes(w http.ResponseWriter, r *http.Request) {
	rows, err := DB.Query("SELECT id, name, type, address, clean_ip, port, transport, security, path, host, pbk, sid, flow, fingerprint, token, status FROM nodes")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var nodeList []Node
	for rows.Next() {
		var n Node
		rows.Scan(&n.ID, &n.Name, &n.Type, &n.Address, &n.CleanIP, &n.Port, &n.Transport, &n.Security, &n.Path, &n.Host, &n.Pbk, &n.Sid, &n.Flow, &n.Fingerprint, &n.Token, &n.Status)
		nodeList = append(nodeList, n)
	}

	if nodeList == nil {
		nodeList = []Node{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(nodeList)
}

func handleCreateNode(w http.ResponseWriter, r *http.Request) {
	var n Node
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newID := uuid.New().String()
	token := generateToken()

	if n.Fingerprint == "" {
		n.Fingerprint = "chrome"
	}

	_, err := DB.Exec(`INSERT INTO nodes 
		(id, name, type, address, clean_ip, port, transport, security, path, host, pbk, sid, flow, fingerprint, token) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, 
		newID, n.Name, n.Type, n.Address, n.CleanIP, n.Port, n.Transport, n.Security, n.Path, n.Host, n.Pbk, n.Sid, n.Flow, n.Fingerprint, token)
	
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	DB.Exec("DELETE FROM node_usage WHERE node_id = ?", id)
	DB.Exec("DELETE FROM nodes WHERE id = ?", id)
	w.WriteHeader(http.StatusOK)
}

func handleEditNode(w http.ResponseWriter, r *http.Request) {
	var n Node
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err := DB.Exec(`UPDATE nodes SET 
		name = ?, address = ?, clean_ip = ?, port = ?, transport = ?, security = ?, path = ?, host = ?, pbk = ?, sid = ?, flow = ?, fingerprint = ? 
		WHERE id = ?`, 
		n.Name, n.Address, n.CleanIP, n.Port, n.Transport, n.Security, n.Path, n.Host, n.Pbk, n.Sid, n.Flow, n.Fingerprint, n.ID)
	
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func handleNodeSync(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) < 8 || authHeader[:7] != "Bearer " {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	token := authHeader[7:]

	_, err := ValidateNodeToken(token)
	if err != nil {
		http.Error(w, "Invalid Token", http.StatusUnauthorized)
		return
	}

	rows, err := DB.Query("SELECT id, expire_time FROM users WHERE status = 'active'")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var activeUUIDs []string
	now := time.Now().Unix()

	for rows.Next() {
		var id string
		var exp int64
		rows.Scan(&id, &exp)
		if exp == 0 || exp > now {
			activeUUIDs = append(activeUUIDs, id)
		}
	}

	if activeUUIDs == nil {
		activeUUIDs = []string{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"uuids": activeUUIDs,
	})
}

func handleReportUsage(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) < 8 || authHeader[:7] != "Bearer " {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	token := authHeader[7:]

	nodeID, err := ValidateNodeToken(token)
	if err != nil {
		http.Error(w, "Invalid Token", http.StatusUnauthorized)
		return
	}

	var req []struct {
		UserID    string `json:"user_id"`
		BytesUsed int64  `json:"bytes_used"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	for _, usage := range req {
		RecordUsage(usage.UserID, nodeID, usage.BytesUsed)
	}

	w.WriteHeader(http.StatusOK)
}

// موتور ارتقا یافته با xhttp، splithttp و uTLS
func handleSubscription(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	if userID == "" {
		http.Error(w, "Missing User ID", http.StatusBadRequest)
		return
	}

	var status, customRemark string
	var expireTime int64
	var vlessEnabled, trojanEnabled, vmessEnabled int

	err := DB.QueryRow("SELECT status, expire_time, vless_enabled, trojan_enabled, vmess_enabled, custom_remark FROM users WHERE id = ?", userID).Scan(&status, &expireTime, &vlessEnabled, &trojanEnabled, &vmessEnabled, &customRemark)
	if err != nil || status != "active" {
		http.Error(w, "User is inactive or not found", http.StatusNotFound)
		return
	}
	if expireTime > 0 && time.Now().Unix() > expireTime {
		http.Error(w, "Subscription Expired", 403)
		return
	}

	settings := loadSettingsFromDB()

	rows, err := DB.Query("SELECT name, type, address, clean_ip, port, transport, security, path, host, pbk, sid, flow, fingerprint FROM nodes WHERE status = 'active'")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var configs []string

	for rows.Next() {
		var n Node
		rows.Scan(&n.Name, &n.Type, &n.Address, &n.CleanIP, &n.Port, &n.Transport, &n.Security, &n.Path, &n.Host, &n.Pbk, &n.Sid, &n.Flow, &n.Fingerprint)

		// موتور فعلی (main.go handleProxy و worker.js) فقط هندشیک روی WebSocket ساده رو
		// پیاده‌سازی کرده و TLS هم توسط خودِ Railway/Cloudflare در لبه انجام میشه (wss://).
		// gRPC/XHTTP/SplitHTTP/REALITY نیاز به یه موتور واقعی مثل xray-core دارن که فعلاً
		// وجود نداره؛ تا وقتی اضافه نشده، از تولید کانفیگ برای اون‌ها صرف‌نظر می‌کنیم تا
		// کاربر سابسکریپشنی نگیره که اصلاً وصل نمیشه.
		if n.Transport != "ws" || n.Security != "tls" {
			continue
		}

		safeAddr := cleanDomain(n.Address)
		targetIP := safeAddr

		if n.CleanIP != "" {
			targetIP = cleanDomain(n.CleanIP)
		} else if settings.DefaultCleanIp != "" {
			targetIP = cleanDomain(settings.DefaultCleanIp)
		}

		remarkName := n.Name
		if strings.TrimSpace(customRemark) != "" {
			remarkName = strings.TrimSpace(customRemark)
		}

		q := url.Values{}
		q.Add("type", n.Transport)
		q.Add("security", n.Security)
		q.Add("encryption", "none")

		// هندل کردن ترنسپورت‌های جدید: xhttp و splithttp
		if n.Transport == "ws" || n.Transport == "xhttp" || n.Transport == "splithttp" {
			q.Add("path", n.Path)
			if n.Host != "" { q.Add("host", n.Host) } else { q.Add("host", safeAddr) }
		} else if n.Transport == "grpc" {
			q.Add("serviceName", n.Path)
			q.Add("mode", "multi")
		}

		// هندل کردن امنیت و uTLS Fingerprint
		if n.Security == "tls" || n.Security == "reality" {
			if n.Host != "" { q.Add("sni", n.Host) } else { q.Add("sni", safeAddr) }
			
			fp := n.Fingerprint
			if fp == "" { fp = "chrome" }
			q.Add("fp", fp)
			
			// اضافه کردن استاندارد ALPN برای xhttp و splithttp جهت سرعت و عبور بهتر
			if n.Transport == "xhttp" || n.Transport == "splithttp" {
				q.Add("alpn", "h2,http/1.1")
			}
		}

		if n.Security == "reality" {
			q.Add("pbk", n.Pbk)
			q.Add("sid", n.Sid)
			if n.Flow != "" { q.Add("flow", n.Flow) }
		}

		queryString := q.Encode()

		if vlessEnabled == 1 {
			vlessUrl := fmt.Sprintf("vless://%s@%s:%d?%s#%s-VLESS", userID, targetIP, n.Port, queryString, url.PathEscape(remarkName))
			configs = append(configs, vlessUrl)
		}
		
		if trojanEnabled == 1 {
			trojanUrl := fmt.Sprintf("trojan://%s@%s:%d?%s#%s-Trojan", userID, targetIP, n.Port, queryString, url.PathEscape(remarkName))
			configs = append(configs, trojanUrl)
		}

		if vmessEnabled == 1 {
			sniVal := safeAddr
			if n.Host != "" { sniVal = n.Host }
			
			vmessObj := VMessConfig{
				V:    "2",
				Ps:   remarkName + "-VMess",
				Add:  targetIP,
				Port: fmt.Sprint(n.Port),
				Id:   userID,
				Net:  n.Transport,
				Type: "none",
				Host: sniVal,
				Path: n.Path,
				Tls:  n.Security,
				Sni:  sniVal,
			}
			
			vmessJson, _ := json.Marshal(vmessObj)
			vmessBase64 := base64.StdEncoding.EncodeToString(vmessJson)
			configs = append(configs, "vmess://"+vmessBase64)
		}
	}

	finalStr := strings.Join(configs, "\n")
	encodedSub := base64.StdEncoding.EncodeToString([]byte(finalStr))

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(encodedSub))
}