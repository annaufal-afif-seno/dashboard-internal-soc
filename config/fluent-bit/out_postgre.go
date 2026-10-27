package main

import (
	"C"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/fluent/fluent-bit-go/output"
	_ "github.com/lib/pq"
)

var (
	pgDB *sql.DB

	// Automatic failover & leader election state.
	// Semua instance Fluent Bit pada cluster Wazuh tetap RUNNING;
	// hanya node yang memegang status LEADER di PostgreSQL yang aktif menulis ke database.
	nodeID             string
	nodePriority       int
	checkWazuhProcess  bool
	disableLeaderElect bool
	targetTable        string
	leaderDocumentID   string

	leaderMu   sync.RWMutex
	isLeader   bool
	leaderStop chan struct{}
	leaderDone chan struct{}
)

const (
	defaultLeaderDocumentID = "wazuh-ingestion"
	leaderHeartbeat         = 5 * time.Second
	leaderLease             = 15 * time.Second
	defaultTargetTable      = "telemetry.raw_events"
)

//export FLBPluginRegister
func FLBPluginRegister(def unsafe.Pointer) int {
	return output.FLBPluginRegister(def, "out_postgre", "PostgreSQL Wazuh Raw Telemetry Output Plugin (ASOC 7-Schema Architecture with HA Failover)")
}

//export FLBPluginInit
func FLBPluginInit(plugin unsafe.Pointer) int {
	// 1. Ambil URI PostgreSQL dari konfigurasi Fluent Bit atau environment variable
	uri := output.FLBPluginConfigKey(plugin, "Uri")
	if uri == "" {
		uri = os.Getenv("PG_URI")
	}

	// 2. Jika Uri tidak diisi, susun otomatis dari parameter komponen (Host, Port, User, Password, Database)
	if uri == "" {
		host := firstNonEmpty(output.FLBPluginConfigKey(plugin, "Host"), os.Getenv("PG_HOST"), "127.0.0.1")
		port := firstNonEmpty(output.FLBPluginConfigKey(plugin, "Port"), os.Getenv("PG_PORT"), "5432")
		user := firstNonEmpty(output.FLBPluginConfigKey(plugin, "User"), os.Getenv("PG_USER"), "postgres")
		pass := firstNonEmpty(output.FLBPluginConfigKey(plugin, "Password"), os.Getenv("PG_PASS"), "")
		dbName := firstNonEmpty(output.FLBPluginConfigKey(plugin, "Database"), os.Getenv("PG_DB"), "wazuh_soc_db")
		sslMode := firstNonEmpty(output.FLBPluginConfigKey(plugin, "SslMode"), os.Getenv("PG_SSLMODE"), "disable")

		uri = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", user, pass, host, port, dbName, sslMode)
	}

	var err error
	pgDB, err = sql.Open("postgres", uri)
	if err != nil {
		fmt.Printf("[out_postgre] ERROR: PostgreSQL open connection failed: %v\n", err)
		return output.FLB_ERROR
	}

	pgDB.SetMaxOpenConns(25)
	pgDB.SetMaxIdleConns(10)
	pgDB.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := pgDB.PingContext(ctx); err != nil {
		fmt.Printf("[out_postgre] ERROR: PostgreSQL ping failed: %v\n", err)
		return output.FLB_ERROR
	}

	// 3. Konfigurasi Tabel Tujuan (Default: telemetry.raw_events)
	targetTable = firstNonEmpty(output.FLBPluginConfigKey(plugin, "Table"), os.Getenv("TARGET_TABLE"), defaultTargetTable)

	// 4. Konfigurasi Identitas Node & Leader Election
	nodeID = firstNonEmpty(output.FLBPluginConfigKey(plugin, "Node_ID"), os.Getenv("NODE_ID"))
	if nodeID == "" {
		if hostName, err := os.Hostname(); err == nil && hostName != "" {
			nodeID = hostName
		} else {
			nodeID = "wazuh-node-1"
		}
		fmt.Printf("[out_postgre] INFO: NODE_ID not set, defaulting to %q\n", nodeID)
	}

	priorityStr := firstNonEmpty(output.FLBPluginConfigKey(plugin, "Node_Priority"), os.Getenv("NODE_PRIORITY"))
	if priorityStr == "" {
		nodePriority = 100
	} else {
		if _, err := fmt.Sscanf(priorityStr, "%d", &nodePriority); err != nil || nodePriority <= 0 {
			nodePriority = 100
		}
	}

	disableLeaderElectStr := strings.ToLower(firstNonEmpty(output.FLBPluginConfigKey(plugin, "Disable_Leader_Election"), os.Getenv("DISABLE_LEADER_ELECTION"), "false"))
	disableLeaderElect = disableLeaderElectStr == "true" || disableLeaderElectStr == "1" || disableLeaderElectStr == "yes"

	checkWazuhStr := strings.ToLower(firstNonEmpty(output.FLBPluginConfigKey(plugin, "Check_Wazuh_Process"), os.Getenv("CHECK_WAZUH_PROCESS"), "true"))
	checkWazuhProcess = checkWazuhStr == "true" || checkWazuhStr == "1" || checkWazuhStr == "yes"

	leaderDocumentID = firstNonEmpty(output.FLBPluginConfigKey(plugin, "Leader_ID"), os.Getenv("LEADER_ID"), defaultLeaderDocumentID)

	// 5. Pastikan Skema dan Tabel telemetry.raw_events sudah siap
	if err := ensureTables(); err != nil {
		fmt.Printf("[out_postgre] ERROR: ensureTables failed: %v\n", err)
		return output.FLB_ERROR
	}

	// 6. Inisialisasi Leader Election
	if disableLeaderElect {
		setLeaderState(true)
		fmt.Printf("[out_postgre] Leader election disabled. Node=%s operates in standalone ACTIVE mode.\n", nodeID)
	} else {
		leaderStop = make(chan struct{})
		leaderDone = make(chan struct{})
		if !startLeaderElection() {
			fmt.Println("[out_postgre] ERROR: Initial leader election failed")
			return output.FLB_ERROR
		}
	}

	fmt.Printf("[out_postgre] Initialized successfully -> TargetTable=%s Node=%s Priority=%d (LeaderDoc=%s, Heartbeat=%s, Lease=%s)\n",
		targetTable, nodeID, nodePriority, leaderDocumentID, leaderHeartbeat, leaderLease)
	return output.FLB_OK
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func ensureTables() error {
	queries := []string{
		// 1. Skema Telemetri
		`CREATE SCHEMA IF NOT EXISTS telemetry;`,

		// 2. Tabel Sinkronisasi Leader HA Failover
		`CREATE TABLE IF NOT EXISTS asoc_leader (
			id TEXT PRIMARY KEY,
			node_id TEXT NOT NULL,
			priority INT NOT NULL,
			lease_until TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		);`,

		// 3. Tabel Telemetri Mentah Lengkap (telemetry.raw_events)
		`CREATE TABLE IF NOT EXISTS telemetry.raw_events (
			event_id VARCHAR(64) NOT NULL,
			timestamp TIMESTAMPTZ NOT NULL,
			agent_id VARCHAR(32) NOT NULL DEFAULT '000',
			tenant_id VARCHAR(64) DEFAULT 'DEFAULT',
			agent_name VARCHAR(128),
			agent_ip VARCHAR(45),
			source_ip VARCHAR(45),
			destination_ip VARCHAR(45),
			source_port INT,
			destination_port INT,
			protocol VARCHAR(16),
			username VARCHAR(128),
			location VARCHAR(255),
			decoder_name VARCHAR(64),
			raw_payload TEXT NOT NULL,
			ingested_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
			CONSTRAINT pk_raw_events PRIMARY KEY (event_id, timestamp)
		) PARTITION BY RANGE (timestamp);`,

		// 4. Default Partition (Mencegah kegagalan insert jika partisi bulanan belum dibuat)
		`CREATE TABLE IF NOT EXISTS telemetry.raw_events_default PARTITION OF telemetry.raw_events DEFAULT;`,

		// 5. Indeks Performa Tinggi untuk Pencarian Forensik dan Pipeline
		`CREATE INDEX IF NOT EXISTS idx_raw_events_timestamp ON telemetry.raw_events (timestamp DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_raw_events_agent_id ON telemetry.raw_events (agent_id);`,
		`CREATE INDEX IF NOT EXISTS idx_raw_events_source_ip ON telemetry.raw_events (source_ip) WHERE source_ip IS NOT NULL;`,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, q := range queries {
		if _, err := pgDB.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("failed executing %s: %w", q, err)
		}
	}
	return nil
}

func startLeaderElection() bool {
	if pgDB == nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := pgDB.ExecContext(ctx, `
		INSERT INTO asoc_leader (id, node_id, priority, lease_until, updated_at)
		VALUES ($1, '', 0, TO_TIMESTAMP(0), NOW())
		ON CONFLICT (id) DO NOTHING
	`, leaderDocumentID)
	if err != nil {
		fmt.Printf("[out_postgre] Leader initialization error: %v\n", err)
		return false
	}

	refreshLeadership()

	go func() {
		ticker := time.NewTicker(leaderHeartbeat)
		defer ticker.Stop()
		defer close(leaderDone)

		for {
			select {
			case <-ticker.C:
				refreshLeadership()
			case <-leaderStop:
				return
			}
		}
	}()

	return true
}

func isWazuhManagerActive() bool {
	if !checkWazuhProcess {
		return true
	}

	// 1. Periksa PID file di /var/ossec/var/run
	foundPidFile := false
	if runDir, err := os.Open("/var/ossec/var/run"); err == nil {
		foundPidFile = true
		files, _ := runDir.Readdirnames(100)
		runDir.Close()
		for _, fn := range files {
			if strings.HasSuffix(fn, ".pid") && (strings.HasPrefix(fn, "wazuh-analysisd") || strings.HasPrefix(fn, "wazuh-execd") || strings.HasPrefix(fn, "ossec-analysisd")) {
				var pid int
				parts := strings.Split(strings.TrimSuffix(fn, ".pid"), "-")
				if len(parts) > 1 {
					fmt.Sscanf(parts[len(parts)-1], "%d", &pid)
				}
				if pid <= 0 {
					if data, err := os.ReadFile("/var/ossec/var/run/" + fn); err == nil {
						fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &pid)
					}
				}
				if pid > 0 {
					commPath := fmt.Sprintf("/proc/%d/comm", pid)
					if commBytes, err := os.ReadFile(commPath); err == nil {
						comm := strings.TrimSpace(string(commBytes))
						if strings.Contains(comm, "wazuh") || strings.Contains(comm, "ossec") {
							return true
						}
					}
				}
			}
		}
	}

	// 2. Periksa /proc langsung untuk proses daemons Wazuh
	if procDir, err := os.Open("/proc"); err == nil {
		names, err := procDir.Readdirnames(1000)
		procDir.Close()
		if err == nil {
			for _, name := range names {
				if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
					if commBytes, err := os.ReadFile("/proc/" + name + "/comm"); err == nil {
						comm := strings.TrimSpace(string(commBytes))
						if comm == "wazuh-analysisd" || comm == "wazuh-execd" ||
							comm == "wazuh-modulesd" || comm == "ossec-analysisd" ||
							comm == "wazuh-clusterd" || comm == "wazuh-remoted" {
							return true
						}
					}
				}
			}
		}
	}

	// 3. Fallback sistem systemctl
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "wazuh-manager")
	if cmd.Run() == nil {
		return true
	}

	// Jika direktori /var/ossec tidak ada sama sekali (misal Fluent Bit berjalan di forwarder/container),
	// jangan blokir status leader secara keliru.
	if !foundPidFile {
		return true
	}

	return false
}

func refreshLeadership() {
	if pgDB == nil || nodeID == "" {
		setLeaderState(false)
		return
	}

	managerActive := isWazuhManagerActive()
	if !managerActive {
		if getIsLeader() {
			fmt.Printf("[out_postgre] WAZUH MANAGER STOPPED -> Yielding lease for node=%s (Stepping down to STANDBY)\n", nodeID)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_, _ = pgDB.ExecContext(ctx, `
				UPDATE asoc_leader
				SET lease_until = TO_TIMESTAMP(0), updated_at = NOW()
				WHERE id = $1 AND node_id = $2
			`, leaderDocumentID, nodeID)
			cancel()
		}
		setLeaderState(false)
		return
	}

	now := time.Now().UTC()
	newLease := now.Add(leaderLease)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var currentLeader string
	var currentPriority int

	err := pgDB.QueryRowContext(ctx, `
		UPDATE asoc_leader
		SET node_id = $2, priority = $3, lease_until = $4, updated_at = $5
		WHERE id = $1 AND (
			node_id = $2 OR
			lease_until <= $5 OR
			(priority < $3 AND lease_until > $5)
		)
		RETURNING node_id, priority
	`, leaderDocumentID, nodeID, nodePriority, newLease, now).Scan(&currentLeader, &currentPriority)

	if err == nil {
		leader := currentLeader == nodeID && currentPriority == nodePriority
		setLeaderState(leader)
		if leader {
			fmt.Printf("[out_postgre] LEADER ACTIVE -> node=%s priority=%d (Wazuh: ACTIVE) lease_until=%s\n",
				nodeID, nodePriority, newLease.Format(time.RFC3339))
		}
		return
	}

	if err == sql.ErrNoRows {
		setLeaderState(false)
		var holder string
		var holderPrio int
		if qErr := pgDB.QueryRowContext(ctx, `SELECT node_id, priority FROM asoc_leader WHERE id = $1`, leaderDocumentID).Scan(&holder, &holderPrio); qErr == nil {
			fmt.Printf("[out_postgre] STANDBY -> node=%s priority=%d | Active Leader: node=%s priority=%d\n",
				nodeID, nodePriority, holder, holderPrio)
		}
		return
	}

	setLeaderState(false)
	fmt.Printf("[out_postgre] Leader election error: %v -> forcing STANDBY\n", err)
}

func setLeaderState(value bool) {
	leaderMu.Lock()
	changed := isLeader != value
	isLeader = value
	leaderMu.Unlock()

	if changed {
		if value {
			fmt.Printf("[out_postgre] ROLE CHANGE: STANDBY -> ACTIVE (node=%s priority=%d)\n", nodeID, nodePriority)
		} else {
			fmt.Printf("[out_postgre] ROLE CHANGE: ACTIVE -> STANDBY (node=%s priority=%d)\n", nodeID, nodePriority)
		}
	}
}

func getIsLeader() bool {
	leaderMu.RLock()
	defer leaderMu.RUnlock()
	return isLeader
}

func stopLeaderElection() {
	if leaderStop != nil {
		select {
		case <-leaderStop:
		default:
			close(leaderStop)
		}
	}
	if leaderDone != nil {
		select {
		case <-leaderDone:
		case <-time.After(2 * time.Second):
		}
	}
	setLeaderState(false)
}

//export FLBPluginFlush
func FLBPluginFlush(data unsafe.Pointer, length C.int, tag *C.char) int {
	// Jika bukan node Leader, lewati eksekusi agar tidak terjadi duplikasi insert
	if !getIsLeader() {
		return output.FLB_OK
	}

	dec := output.NewDecoder(data, int(length))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tx, err := pgDB.BeginTx(ctx, nil)
	if err != nil {
		fmt.Printf("[out_postgre] BeginTx error: %v\n", err)
		return output.FLB_RETRY
	}

	insertSQL := fmt.Sprintf(`
		INSERT INTO %s (
			event_id, timestamp, agent_id, tenant_id, agent_name, agent_ip,
			source_ip, destination_ip, source_port, destination_port,
			protocol, username, location, decoder_name, raw_payload, ingested_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NOW())
		ON CONFLICT (event_id, timestamp) DO NOTHING;
	`, targetTable)

	stmt, err := tx.PrepareContext(ctx, insertSQL)
	if err != nil {
		_ = tx.Rollback()
		fmt.Printf("[out_postgre] PrepareContext error: %v\n", err)
		return output.FLB_RETRY
	}
	defer stmt.Close()

	insertedCount := 0
	rowIdx := 0

	for {
		ret, ts, record := output.GetRecord(dec)
		if ret != 0 {
			break
		}
		rowIdx++

		m := parseRecord(record)
		if len(m) == 0 {
			continue
		}

		// ZERO ALERT DROP: Tarik semua alert tanpa terkecuali (Level 0 s/d 16, termasuk Agent 000)
		eventDT := parseTimestamp(m, ts)

		// 1. Ekstraksi Informasi Agen
		agentMap, _ := m["agent"].(map[string]interface{})
		agentID := toString(agentMap["id"])
		if agentID == "" {
			agentID = "000"
		}
		if len(agentID) > 32 {
			agentID = agentID[:32]
		}

		agentName := toString(agentMap["name"])
		if agentName == "" && agentID == "000" {
			agentName = "wazuh-manager"
		}
		if len(agentName) > 128 {
			agentName = agentName[:128]
		}

		agentIP := toString(agentMap["ip"])
		if len(agentIP) > 45 {
			agentIP = agentIP[:45]
		}

		// 2. Ekstraksi Event ID
		eventID := toString(m["id"])
		if eventID == "" {
			eventID = toString(m["_id"])
		}
		if eventID == "" {
			eventID = fmt.Sprintf("FLB-%s-%d-%d", agentID, eventDT.UnixNano(), rowIdx)
		}
		if len(eventID) > 64 {
			eventID = eventID[:64]
		}

		// 3. Ekstraksi Tenant ID
		tenantID := ""
		if labelsMap, ok := agentMap["labels"].(map[string]interface{}); ok {
			tenantID = toString(labelsMap["tenant"])
		}
		dataMap, _ := m["data"].(map[string]interface{})
		if tenantID == "" && dataMap != nil {
			tenantID = toString(dataMap["tenant"])
		}
		if tenantID == "" {
			tenantID = toString(m["tenant"])
		}
		if tenantID == "" {
			tenantID = "DEFAULT"
		}
		if len(tenantID) > 64 {
			tenantID = tenantID[:64]
		}

		// 4. Ekstraksi Jaringan & Aktor (Kompatibel dengan ECS & Common Event Model)
		srcIP := extractAliasedString(dataMap, m, []string{
			"srcip", "src_ip", "client_ip", "clientip", "remote_addr", "remote_ip",
			"c-ip", "source.ip", "ipAddress", "sourceIp", "addr", "caller_ip",
		})
		if len(srcIP) > 45 {
			srcIP = srcIP[:45]
		}

		dstIP := extractAliasedString(dataMap, m, []string{
			"dstip", "dst_ip", "server_ip", "destinationIp", "destination_ip", "dest_ip",
			"dest.ip", "target_ip", "cs-host", "host_ip",
		})
		if len(dstIP) > 45 {
			dstIP = dstIP[:45]
		}

		srcPort := extractPort(dataMap, []string{"srcport", "src_port", "sourcePort", "client_port", "c-port"})
		dstPort := extractPort(dataMap, []string{"dstport", "dst_port", "destinationPort", "server_port", "s-port"})

		protocol := extractAliasedString(dataMap, m, []string{"proto", "protocol", "network.protocol"})
		if len(protocol) > 16 {
			protocol = protocol[:16]
		}

		username := extractAliasedString(dataMap, m, []string{
			"dstuser", "srcuser", "username", "user", "targetUserName", "subjectUserName",
			"account", "acct", "auid", "user_name", "login",
		})
		if len(username) > 128 {
			username = username[:128]
		}

		location := toString(m["location"])
		if len(location) > 255 {
			location = location[:255]
		}

		decoderMap, _ := m["decoder"].(map[string]interface{})
		decoderName := toString(decoderMap["name"])
		if decoderName == "" {
			decoderName = toString(m["decoder"])
		}
		if len(decoderName) > 64 {
			decoderName = decoderName[:64]
		}

		// 5. Raw Payload Lengkap (Non-Repudiation Forensics)
		var rawPayload string
		if payloadBytes, err := json.Marshal(m); err == nil && len(payloadBytes) > 2 {
			rawPayload = string(payloadBytes)
		} else {
			rawPayload = toString(m["full_log"])
			if rawPayload == "" {
				rawPayload = toString(m["log"])
			}
			if rawPayload == "" {
				rawPayload = "{}"
			}
		}

		// Eksekusi insert batch
		_, err = stmt.ExecContext(ctx,
			eventID,
			eventDT,
			agentID,
			tenantID,
			nullableString(agentName),
			nullableString(agentIP),
			nullableString(srcIP),
			nullableString(dstIP),
			srcPort,
			dstPort,
			nullableString(protocol),
			nullableString(username),
			nullableString(location),
			nullableString(decoderName),
			rawPayload,
		)
		if err != nil {
			fmt.Printf("[out_postgre] Row insert error (event_id=%s): %v\n", eventID, err)
		} else {
			insertedCount++
		}
	}

	if err := tx.Commit(); err != nil {
		fmt.Printf("[out_postgre] Transaction commit error: %v\n", err)
		return output.FLB_RETRY
	}

	if insertedCount > 0 {
		fmt.Printf("[out_postgre] [INGEST] Committed %d raw alerts -> %s | Node: %s\n",
			insertedCount, targetTable, nodeID)
	}

	return output.FLB_OK
}

//export FLBPluginExit
func FLBPluginExit() int {
	stopLeaderElection()

	if pgDB != nil && nodeID != "" && !disableLeaderElect {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _ = pgDB.ExecContext(ctx, `
			UPDATE asoc_leader
			SET lease_until = TO_TIMESTAMP(0), updated_at = NOW()
			WHERE id = $1 AND node_id = $2
		`, leaderDocumentID, nodeID)
		cancel()
	}

	if pgDB != nil {
		pgDB.Close()
	}
	return output.FLB_OK
}

// Helper: Konversi interface{} ke string
func toString(val interface{}) string {
	if val == nil {
		return ""
	}
	switch v := val.(type) {
	case string:
		return strings.TrimSpace(v)
	case []byte:
		return strings.TrimSpace(string(v))
	default:
		s := strings.TrimSpace(fmt.Sprintf("%v", v))
		if s == "<nil>" {
			return ""
		}
		return s
	}
}

// Helper: Nilai string yang jika kosong menjadi SQL NULL
func nullableString(s string) interface{} {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.TrimSpace(s)
}

// Helper: Ekstraksi port jaringan dengan validasi 1-65535 (menghasilkan SQL NULL jika invalid)
func extractPort(dataMap map[string]interface{}, aliases []string) interface{} {
	if dataMap == nil {
		return nil
	}
	for _, alias := range aliases {
		if val, ok := dataMap[alias]; ok && val != nil {
			switch v := val.(type) {
			case int:
				if v > 0 && v <= 65535 {
					return v
				}
			case int64:
				if v > 0 && v <= 65535 {
					return int(v)
				}
			case float64:
				if v > 0 && v <= 65535 {
					return int(v)
				}
			case string:
				if p, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && p > 0 && p <= 65535 {
					return p
				}
			}
		}
	}
	return nil
}

// Helper: Pencarian rekursif field berbasis daftar alias (ECS & Common Event Model)
func extractAliasedString(dataMap map[string]interface{}, rootMap map[string]interface{}, aliases []string) string {
	// 1. Cek di dalam dataMap
	if dataMap != nil {
		for _, alias := range aliases {
			if val, ok := dataMap[alias]; ok && val != nil {
				if s := toString(val); s != "" && s != "-" && s != "null" {
					return s
				}
			}
		}
		// Cek nested win.eventdata jika ada
		if win, ok := dataMap["win"].(map[string]interface{}); ok {
			if ed, ok := win["eventdata"].(map[string]interface{}); ok {
				for _, alias := range aliases {
					if val, ok := ed[alias]; ok && val != nil {
						if s := toString(val); s != "" && s != "-" && s != "null" {
							return s
						}
					}
				}
			}
		}
	}

	// 2. Cek di root alert map
	if rootMap != nil {
		for _, alias := range aliases {
			if val, ok := rootMap[alias]; ok && val != nil {
				if s := toString(val); s != "" && s != "-" && s != "null" {
					return s
				}
			}
		}
	}

	return ""
}

// Helper: Parsing timestamp dengan berbagai variasi layout format Wazuh JSON
func parseTimestamp(m map[string]interface{}, ts interface{}) time.Time {
	var detectedAt time.Time
	tsStr := toString(m["timestamp"])
	if tsStr == "" {
		tsStr = toString(m["@timestamp"])
	}

	if len(tsStr) >= 10 {
		layouts := []string{
			"2006-01-02T15:04:05.000-0700",
			"2006-01-02T15:04:05.000+0000",
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02T15:04:05.000000Z",
			"2006-01-02T15:04:05.000Z",
			"2006-01-02T15:04:05Z",
			"2006-01-02 15:04:05.000000",
			"2006-01-02 15:04:05",
		}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, tsStr); err == nil {
				detectedAt = t.UTC()
				break
			}
		}
	}

	if detectedAt.IsZero() {
		switch t := ts.(type) {
		case output.FLBTime:
			detectedAt = t.Time.UTC()
		case time.Time:
			detectedAt = t.UTC()
		default:
			detectedAt = time.Now().UTC()
		}
	}
	return detectedAt
}

// Helper: Rekursif parse map[interface{}]interface{} dari Fluent Bit decoder ke map[string]interface{}
func parseRecord(record map[interface{}]interface{}) map[string]interface{} {
	m := make(map[string]interface{})
	for k, v := range record {
		keyStr := toString(k)
		switch val := v.(type) {
		case map[interface{}]interface{}:
			m[keyStr] = parseRecord(val)
		case []interface{}:
			var arr []interface{}
			for _, elem := range val {
				if elemMap, ok := elem.(map[interface{}]interface{}); ok {
					arr = append(arr, parseRecord(elemMap))
				} else if elemBytes, ok := elem.([]byte); ok {
					arr = append(arr, string(elemBytes))
				} else {
					arr = append(arr, elem)
				}
			}
			m[keyStr] = arr
		case []byte:
			m[keyStr] = string(val)
		default:
			m[keyStr] = v
		}
	}
	return m
}

func main() {}
