package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Token 是拆开后的 JWT。Raw* 保留原始分段，方便原样输出。
type Token struct {
	Header    map[string]any
	Claims    map[string]any
	RawHeader string
	RawClaims string
	RawSig    string
}

var (
	ErrEmpty     = errors.New("token 为空")
	ErrSegments  = errors.New("JWT 应该是三段（header.payload.signature）")
	ErrBadBase64 = errors.New("base64url 解码失败")
)

// Decode 拆开一个 JWT。只解码，不验签——本地排查用不着密钥。
func Decode(s string) (*Token, error) {
	s = strings.TrimSpace(s)
	// 从 Authorization 头里直接复制出来的通常带 "Bearer " 前缀，帮忙去掉。
	if len(s) > 7 && strings.EqualFold(s[:7], "bearer ") {
		s = strings.TrimSpace(s[7:])
	}
	// 有些日志里 token 会被引号包住。
	s = strings.Trim(s, `"'`)
	if s == "" {
		return nil, ErrEmpty
	}

	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w，实际 %d 段", ErrSegments, len(parts))
	}

	t := &Token{
		RawHeader: parts[0],
		RawClaims: parts[1],
		RawSig:    parts[2],
	}

	h, err := decodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header %w: %v", ErrBadBase64, err)
	}
	if err := json.Unmarshal(h, &t.Header); err != nil {
		return nil, fmt.Errorf("header 不是合法 JSON: %v", err)
	}

	c, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload %w: %v", ErrBadBase64, err)
	}
	if err := json.Unmarshal(c, &t.Claims); err != nil {
		return nil, fmt.Errorf("payload 不是合法 JSON: %v", err)
	}

	return t, nil
}

// decodeSegment 解一段 base64url。
//
// JWT 规定用 base64url 且**不带 padding**，但现实里两种都能碰到：
// 有的库（尤其是老 PHP/Java 实现）会把 '=' 留着，有的地方还会把 token
// 塞进 URL 后被转义成标准 base64 的 '+' '/'。这里都兼容一下，
// 不然遇到一个能在别处正常解析的 token，我们这儿报错就很莫名其妙。
func decodeSegment(seg string) ([]byte, error) {
	seg = strings.TrimRight(seg, "=")
	// 混进了标准 base64 字符就换回 url 安全的。
	seg = strings.NewReplacer("+", "-", "/", "_").Replace(seg)
	return base64.RawURLEncoding.DecodeString(seg)
}

// Alg 返回签名算法，取不到就是 "?"。
func (t *Token) Alg() string {
	if v, ok := t.Header["alg"].(string); ok && v != "" {
		return v
	}
	return "?"
}

// IsNoneAlg 判断是不是 alg=none。
//
// 这是个真实存在的漏洞模式：攻击者把 alg 改成 none、signature 留空，
// 有些库就直接放行了。排查 token 时这个必须显眼提示。
func (t *Token) IsNoneAlg() bool {
	return strings.EqualFold(t.Alg(), "none")
}

// timeClaim 取出 exp/iat/nbf 这类时间字段。
//
// 坑：encoding/json 把数字都解成 float64。1700000000 这种秒级时间戳
// float64 存得下（精度 53 位），但不能直接类型断言成 int64，
// 会 panic 或者拿到零值。另外有些实现会把时间戳写成字符串。
func (t *Token) timeClaim(name string) (time.Time, bool) {
	v, ok := t.Claims[name]
	if !ok {
		return time.Time{}, false
	}
	switch n := v.(type) {
	case float64:
		return time.Unix(int64(n), 0), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(i, 0), true
	case string:
		// 少数实现写成字符串，容忍一下。
		var i int64
		if _, err := fmt.Sscanf(n, "%d", &i); err == nil {
			return time.Unix(i, 0), true
		}
	}
	return time.Time{}, false
}

// ExpiresAt 返回过期时间。
func (t *Token) ExpiresAt() (time.Time, bool) { return t.timeClaim("exp") }

// IssuedAt 返回签发时间。
func (t *Token) IssuedAt() (time.Time, bool) { return t.timeClaim("iat") }

// NotBefore 返回生效时间。
func (t *Token) NotBefore() (time.Time, bool) { return t.timeClaim("nbf") }

// Status 描述 token 在 now 这一刻的有效性。
type Status struct {
	Expired   bool
	NotYet    bool // 还没到 nbf
	NoExp     bool // 压根没有 exp 字段
	ExpiresAt time.Time
	Remaining time.Duration
}

// Check 判断 token 此刻是否可用。
func (t *Token) Check(now time.Time) Status {
	var s Status

	if nbf, ok := t.NotBefore(); ok && now.Before(nbf) {
		s.NotYet = true
	}

	exp, ok := t.ExpiresAt()
	if !ok {
		s.NoExp = true
		return s
	}
	s.ExpiresAt = exp
	s.Remaining = exp.Sub(now)
	// 注意用 !After 而不是 Before：正好等于 exp 的那一秒按规范算已过期。
	s.Expired = !now.Before(exp)
	return s
}

// ClaimKeys 返回排好序的 claim 名，保证每次输出顺序一致。
// map 遍历顺序是随机的，不排序的话同一个 token 每次打印顺序都不一样。
func (t *Token) ClaimKeys() []string {
	keys := make([]string, 0, len(t.Claims))
	for k := range t.Claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// humanDuration 把时长说成人话，只保留两级单位。
func humanDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	secs := int(d.Seconds()) % 60

	switch {
	case days > 0:
		return fmt.Sprintf("%d 天 %d 小时", days, hours)
	case hours > 0:
		return fmt.Sprintf("%d 小时 %d 分", hours, mins)
	case mins > 0:
		return fmt.Sprintf("%d 分 %d 秒", mins, secs)
	default:
		return fmt.Sprintf("%d 秒", secs)
	}
}
