# go-jwt

又在终端里为个编码解码去开浏览器搜网页？别了，一行命令的事。

把 JWT 拆开看里面装了什么。纯本地，不联网，不需要密钥。

排查登录问题时经常要确认 token 到底过没过期、里面的 uid 对不对。
为了看一眼就把生产 token 贴到在线解析网站，这事本身就是个安全事故。

```powershell
go run . eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.xxx
```

```
算法    : HS256
类型    : JWT

载荷:
  exp:       1.7e+09  (2023-11-15 06:13:20)
  name:      张三
  sub:       1234

状态    : 已过期（2 天 5 小时前）
```

## 用法

```powershell
go run . <token>              # 直接传
echo $token | go run .        # 从管道读
go run . -json <token>        # 输出原始 JSON
go run . -utc <token>         # 时间按 UTC 显示
go run . -q <token>           # 只判断有效性，看退出码
```

`-q` 的退出码：`0` 有效，`2` 已过期。写脚本时好用：

```powershell
go run . -q $token
if ($LASTEXITCODE -eq 2) { "该刷新 token 了" }
```

## 输入容错

从日志或者 curl 命令里直接复制出来的 token 往往不干净，这些都能直接吃下：

- `Bearer eyJ...` —— 自动去掉前缀
- `"eyJ..."` —— 自动去掉引号
- 带 `=` padding —— 规范说不该有，但老的 PHP/Java 实现经常留着
- 含 `+` `/` —— token 塞进 URL 再取出来时会被还原成标准 base64

## 会提示的问题

**`alg=none`** —— 攻击者把算法改成 none、签名段留空，有些库会直接放行。
碰到这种 token 会显眼提示。

**`nbf` 还没到** —— token 本身没过期，但还没到生效时间，现在用一样会被拒。
这种情况报错信息通常很含糊，容易查半天。

## 注意

只解码，**不验签**。签名对不对得拿密钥去服务端验，这个工具管不了。
它解决的是"我想知道这 token 里是什么"，不是"这 token 是否可信"。

## 测试

```powershell
go test ./...
```
