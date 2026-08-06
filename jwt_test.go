package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// makeToken 拼一个测试用 token，签名段随便填，反正我们不验签。
func makeToken(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	enc := func(m map[string]any) string {
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(header) + "." + enc(claims) + ".c2ln"
}

func TestDecodeBasic(t *testing.T) {
	tok, err := Decode(makeToken(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"sub": "1234", "name": "张三"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if tok.Alg() != "HS256" {
		t.Errorf("alg = %q，想要 HS256", tok.Alg())
	}
	if tok.Claims["name"] != "张三" {
		t.Errorf("name = %v，想要 张三", tok.Claims["name"])
	}
}

// JWT 规范说不带 padding，但现实中带 '=' 的 token 到处都是。
// 之前如果直接用 base64.RawURLEncoding，这种 token 会解码失败。
func TestDecodeToleratesPadding(t *testing.T) {
	header := base64.URLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	claims := base64.URLEncoding.EncodeToString([]byte(`{"sub":"a"}`))
	if !strings.Contains(header+claims, "=") {
		t.Skip("这组数据没产生 padding，换一组")
	}
	if _, err := Decode(header + "." + claims + ".x"); err != nil {
		t.Fatalf("带 padding 的 token 应该能解开: %v", err)
	}
}

// token 被塞进 URL 再取出来时，'-' '_' 可能已经变回 '+' '/'。
func TestDecodeToleratesStandardBase64Chars(t *testing.T) {
	// 这段数据编码出来会含 '+' 和 '/'，正好模拟被 URL 还原后的样子。
	payload := []byte(`{"sub":"?????>>>>"}`)
	std := base64.StdEncoding.EncodeToString(payload)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))

	tok, err := Decode(header + "." + std + ".x")
	if err != nil {
		t.Fatalf("含标准 base64 字符的 token 应该能解开: %v", err)
	}
	if tok.Claims["sub"] != "?????>>>>" {
		t.Errorf("sub = %v", tok.Claims["sub"])
	}
}

func TestDecodeStripsBearerPrefix(t *testing.T) {
	raw := makeToken(t, map[string]any{"alg": "HS256"}, map[string]any{"sub": "x"})
	for _, prefix := range []string{"Bearer ", "bearer ", "BEARER "} {
		if _, err := Decode(prefix + raw); err != nil {
			t.Errorf("前缀 %q 应该被去掉: %v", prefix, err)
		}
	}
}

func TestDecodeStripsQuotes(t *testing.T) {
	raw := makeToken(t, map[string]any{"alg": "HS256"}, map[string]any{"sub": "x"})
	if _, err := Decode(`"` + raw + `"`); err != nil {
		t.Errorf("带引号的 token 应该能解开: %v", err)
	}
}

func TestDecodeRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"空串", "", ErrEmpty},
		{"只有空格", "   ", ErrEmpty},
		{"两段", "aaa.bbb", ErrSegments},
		{"四段", "a.b.c.d", ErrSegments},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Decode(c.in)
			if !errors.Is(err, c.want) {
				t.Errorf("err = %v，想要 %v", err, c.want)
			}
		})
	}
}

func TestDecodeRejectsNonJSONPayload(t *testing.T) {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	bad := base64.RawURLEncoding.EncodeToString([]byte(`这不是JSON`))
	if _, err := Decode(h + "." + bad + ".x"); err == nil {
		t.Fatal("payload 不是 JSON 时应该报错")
	}
}

// exp 是 float64，不能直接断言成 int64。这里确认时间取得对。
func TestExpiresAtParsesFloat64(t *testing.T) {
	want := time.Unix(1700000000, 0)
	tok, err := Decode(makeToken(t,
		map[string]any{"alg": "HS256"},
		map[string]any{"exp": 1700000000},
	))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := tok.ExpiresAt()
	if !ok {
		t.Fatal("应该能取到 exp")
	}
	if !got.Equal(want) {
		t.Errorf("exp = %v，想要 %v", got, want)
	}
}

// 有些实现把时间戳写成字符串。
func TestExpiresAtParsesString(t *testing.T) {
	tok, err := Decode(makeToken(t,
		map[string]any{"alg": "HS256"},
		map[string]any{"exp": "1700000000"},
	))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := tok.ExpiresAt()
	if !ok || !got.Equal(time.Unix(1700000000, 0)) {
		t.Errorf("字符串形式的 exp 也应该能解析，得到 %v ok=%v", got, ok)
	}
}

func TestCheckExpired(t *testing.T) {
	now := time.Unix(1700000000, 0)
	tok, err := Decode(makeToken(t,
		map[string]any{"alg": "HS256"},
		map[string]any{"exp": 1699999999},
	))
	if err != nil {
		t.Fatal(err)
	}
	if st := tok.Check(now); !st.Expired {
		t.Error("过期一秒的 token 应该判为已过期")
	}
}

// 边界：现在正好等于 exp。按规范这一刻已经过期了。
func TestCheckExactlyAtExpiry(t *testing.T) {
	now := time.Unix(1700000000, 0)
	tok, err := Decode(makeToken(t,
		map[string]any{"alg": "HS256"},
		map[string]any{"exp": 1700000000},
	))
	if err != nil {
		t.Fatal(err)
	}
	if st := tok.Check(now); !st.Expired {
		t.Error("now == exp 时应该算已过期，不是还有效")
	}
}

func TestCheckValid(t *testing.T) {
	now := time.Unix(1700000000, 0)
	tok, err := Decode(makeToken(t,
		map[string]any{"alg": "HS256"},
		map[string]any{"exp": 1700003600},
	))
	if err != nil {
		t.Fatal(err)
	}
	st := tok.Check(now)
	if st.Expired {
		t.Error("还有一小时的 token 不该判为过期")
	}
	if st.Remaining != time.Hour {
		t.Errorf("剩余 = %v，想要 1h", st.Remaining)
	}
}

func TestCheckNoExp(t *testing.T) {
	tok, err := Decode(makeToken(t,
		map[string]any{"alg": "HS256"},
		map[string]any{"sub": "x"},
	))
	if err != nil {
		t.Fatal(err)
	}
	st := tok.Check(time.Now())
	if !st.NoExp {
		t.Error("没有 exp 时 NoExp 应该为 true")
	}
	if st.Expired {
		t.Error("没有 exp 不代表已过期")
	}
}

func TestCheckNotYetValid(t *testing.T) {
	now := time.Unix(1700000000, 0)
	tok, err := Decode(makeToken(t,
		map[string]any{"alg": "HS256"},
		map[string]any{"nbf": 1700003600, "exp": 1700007200},
	))
	if err != nil {
		t.Fatal(err)
	}
	st := tok.Check(now)
	if !st.NotYet {
		t.Error("nbf 还没到时应该提示")
	}
	if st.Expired {
		t.Error("nbf 没到不等于过期")
	}
}

func TestIsNoneAlg(t *testing.T) {
	for _, alg := range []string{"none", "None", "NONE"} {
		tok, err := Decode(makeToken(t,
			map[string]any{"alg": alg}, map[string]any{"sub": "x"}))
		if err != nil {
			t.Fatal(err)
		}
		if !tok.IsNoneAlg() {
			t.Errorf("alg=%q 应该被识别为 none", alg)
		}
	}

	tok, _ := Decode(makeToken(t,
		map[string]any{"alg": "HS256"}, map[string]any{"sub": "x"}))
	if tok.IsNoneAlg() {
		t.Error("HS256 不该被判成 none")
	}
}

// map 遍历是随机的，不排序的话同一个 token 每次打印顺序都不同。
func TestClaimKeysAreSorted(t *testing.T) {
	tok, err := Decode(makeToken(t,
		map[string]any{"alg": "HS256"},
		map[string]any{"zeta": 1, "alpha": 2, "mike": 3},
	))
	if err != nil {
		t.Fatal(err)
	}
	got := tok.ClaimKeys()
	want := []string{"alpha", "mike", "zeta"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("顺序 = %v，想要 %v", got, want)
		}
	}
}

func TestHumanDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "30 秒"},
		{90 * time.Second, "1 分 30 秒"},
		{2*time.Hour + 5*time.Minute, "2 小时 5 分"},
		{50 * time.Hour, "2 天 2 小时"},
		{-30 * time.Second, "30 秒"}, // 负数取绝对值，过期时长也能显示
	}
	for _, c := range cases {
		if got := humanDuration(c.d); got != c.want {
			t.Errorf("humanDuration(%v) = %q，想要 %q", c.d, got, c.want)
		}
	}
}

func TestRunOutputsClaims(t *testing.T) {
	raw := makeToken(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"sub": "u-1", "exp": 1700000000},
	)
	var buf bytes.Buffer
	if err := run([]string{raw}, &buf, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"HS256", "sub", "u-1", "已过期"} {
		if !strings.Contains(out, want) {
			t.Errorf("输出里应该有 %q，实际:\n%s", want, out)
		}
	}
}

func TestRunReadsStdin(t *testing.T) {
	raw := makeToken(t, map[string]any{"alg": "HS256"}, map[string]any{"sub": "x"})
	var buf bytes.Buffer
	// 前面故意放空行，确认会被跳过。
	if err := run(nil, &buf, strings.NewReader("\n\n"+raw+"\n")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "HS256") {
		t.Errorf("从标准输入读失败:\n%s", buf.String())
	}
}

func TestRunJSONMode(t *testing.T) {
	raw := makeToken(t, map[string]any{"alg": "HS256"}, map[string]any{"sub": "x"})
	var buf bytes.Buffer
	if err := run([]string{"-json", raw}, &buf, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("-json 的输出应该是合法 JSON: %v\n%s", err, buf.String())
	}
	if _, ok := got["claims"]; !ok {
		t.Error("JSON 输出里应该有 claims")
	}
}

func TestRunNoInput(t *testing.T) {
	var buf bytes.Buffer
	if err := run(nil, &buf, strings.NewReader("")); err == nil {
		t.Fatal("没有任何输入时应该报错")
	}
}

func TestRunWarnsOnNoneAlg(t *testing.T) {
	raw := makeToken(t, map[string]any{"alg": "none"}, map[string]any{"sub": "x"})
	var buf bytes.Buffer
	if err := run([]string{raw}, &buf, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "警告") {
		t.Errorf("alg=none 应该给出警告，实际:\n%s", buf.String())
	}
}
