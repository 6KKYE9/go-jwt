// go-jwt：把 JWT 拆开看里面装了什么。
//
// 排查登录问题时经常需要确认 token 到底过没过期、里面的 uid 对不对，
// 又不想为了看一眼就跑去在线解析网站——那等于把生产 token 贴给别人。
// 这个工具纯本地跑，不联网、不需要密钥。
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// errExpired 是 -q 模式下表示 token 已过期的哨兵错误，main 据此返回退出码 2。
var errExpired = errors.New("token expired")

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stdin); err != nil {
		if errors.Is(err, errExpired) {
			// -q 模式里已过期用退出码 2 表达，方便脚本判断
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer, in io.Reader) error {
	fs := flag.NewFlagSet("go-jwt", flag.ContinueOnError)
	fs.SetOutput(out)
	var (
		asJSON = fs.Bool("json", false, "输出原始 JSON，方便管道接 jq")
		utc    = fs.Bool("utc", false, "时间用 UTC 显示")
		quiet  = fs.Bool("q", false, "只输出过期与否，用退出码表示（0 有效 / 2 已过期）")
	)
	fs.Usage = func() {
		fmt.Fprintln(out, "用法: go-jwt [选项] <token>")
		fmt.Fprintln(out, "      不传 token 时从标准输入读")
		fmt.Fprintln(out)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	raw, err := readToken(fs.Args(), in)
	if err != nil {
		return err
	}

	tok, err := Decode(raw)
	if err != nil {
		return err
	}

	loc := time.Local
	if *utc {
		loc = time.UTC
	}
	st := tok.Check(time.Now())

	if *quiet {
		if st.Expired {
			fmt.Fprintln(out, "已过期")
			return errExpired
		}
		fmt.Fprintln(out, "有效")
		return nil
	}

	if *asJSON {
		return printJSON(out, tok)
	}
	printHuman(out, tok, st, loc)
	return nil
}

// readToken 决定 token 从哪来：命令行参数优先，否则读标准输入。
func readToken(args []string, in io.Reader) (string, error) {
	if len(args) > 0 {
		return strings.Join(args, " "), nil
	}
	// 从管道读。用 Reader 而不是 ReadAll，是因为 token 可能后面还跟着别的内容，
	// 只取第一个非空行就够了。
	sc := bufio.NewScanner(in)
	// token 可以很长（塞了一堆 claim 的能到几 KB），默认 64KB 上限够用，
	// 但默认的初始 buffer 太小会多次扩容，这里直接给足。
	sc.Buffer(make([]byte, 0, 8*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			return line, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("没有输入，用法: go-jwt <token>")
}

func printJSON(out io.Writer, t *Token) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{
		"header": t.Header,
		"claims": t.Claims,
	})
}

func printHuman(out io.Writer, t *Token, st Status, loc *time.Location) {
	fmt.Fprintf(out, "算法    : %s\n", t.Alg())
	if typ, ok := t.Header["typ"].(string); ok {
		fmt.Fprintf(out, "类型    : %s\n", typ)
	}
	if kid, ok := t.Header["kid"].(string); ok {
		fmt.Fprintf(out, "密钥 ID : %s\n", kid)
	}

	if t.IsNoneAlg() {
		fmt.Fprintln(out, "⚠ 警告  : alg=none，这个 token 没有签名保护")
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "载荷:")
	for _, k := range t.ClaimKeys() {
		v := t.Claims[k]
		// exp/iat/nbf 直接显示成可读时间，否则一串数字还得自己去换算。
		if k == "exp" || k == "iat" || k == "nbf" {
			if ts, ok := t.timeClaim(k); ok {
				fmt.Fprintf(out, "  %-10s %v  (%s)\n", k+":", v,
					ts.In(loc).Format("2006-01-02 15:04:05"))
				continue
			}
		}
		fmt.Fprintf(out, "  %-10s %v\n", k+":", formatClaim(v))
	}

	fmt.Fprintln(out)
	switch {
	case st.NoExp:
		fmt.Fprintln(out, "状态    : 没有 exp 字段，永不过期")
	case st.Expired:
		fmt.Fprintf(out, "状态    : 已过期（%s前）\n", humanDuration(st.Remaining))
	default:
		fmt.Fprintf(out, "状态    : 有效，还剩 %s\n", humanDuration(st.Remaining))
	}
	if st.NotYet {
		fmt.Fprintln(out, "          注意 nbf 还没到，现在用会被拒绝")
	}
}

// formatClaim 让嵌套的对象/数组显示得紧凑些，别撑满一屏。
func formatClaim(v any) string {
	switch v.(type) {
	case map[string]any, []any:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}
		return string(b)
	}
	return fmt.Sprint(v)
}
