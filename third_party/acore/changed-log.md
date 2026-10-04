# 与官网 Acore 的差异（upstream/main a54e1f2 → 本地 main b6ce7bd）

- 路由 ruleTag/规则链：新增 `requireRuleTag`（支持 `!tag` 排除）；`ruleTag` 支持 `+` 前缀，匹配后标记并跳过无 require 的规则；允许无 outbound 的纯标记规则；新增 RuleTagCondition/RuleTagManager 接口与上下文存储，路由器会累积 tag 再继续匹配。
- 路由 `vlessRoute` 快速路由：`vlessRoute` 除了原有 `"53,443,1000-2000"` 端口列表匹配，还支持数组快捷模式，如 `["53:direct", "443,1000-2000:proxy"]`；命中时直接按数组项里的出站 tag 出站，未命中时不强制选路，继续按 `ruleTag` / `requireRuleTag` 规则链往下走；该模式下同一条规则不能再同时设置 `destination/outboundTag/balancerTag`。

- 域名/IP 匹配：DomainMatcher 拆分正/反匹配，新增 `reverse_match` 属性；geosite/ext geosite 支持 `!` 反向匹配；IP 列表支持 `!` 生成 ReverseMatch GeoIP；补充相应单测。

- DNS 解析：ResolvableContext 先使用底层已解析 IP（如 TPROXY/FOLLOWREDIRECT），并根据来源地址族选择只查 A 或 AAAA，同时转发 ruleTag/标记到上下文。

- sendThrough/网关：SenderConfig 增加 `via6`/`via6_cidr` 与配置解析 `sendThrough6`，校验组合（需配 IPv4 sendThrough，禁止非 IPv6/origin）；0.0.0.0/0 视为未指定；出站网关按目标/路由/原始地址族优先 IPv6 或 IPv4，避免 sendThrough 为 0.0.0.0/0 时回退到 IPv6。

- Freedom 出站：配置新增 `testpre`，基于 DestinationOverride 维护带过期时间的预连接池，预连链路写入 ProxyProtocol 头并在关闭时清理；拨号失败仍按原重试逻辑回退。
- 预连接 keepalive：新增 `preConKeep`，默认 25s；设为 `false` 关闭；支持时间格式（如 `1s`/`500ms`），仅对 testpre 预连接生效。
- Blackhole 出站：`response.type` 支持 `http-301`/`http-302` 携带跳转 URL，新增 `redirect_url`（兼容 `url`/`location`），命中时返回 `Location` 响应头。

- Link 包装恢复：routing.Dispatcher 新增 WrapLinkDispatcher 接口并由 DefaultDispatcher 实现；mux server、reverse bridge、VLESS inbound 在内部连接时调用 WrapLink，未实现时 VLESS reverse 明确报错。

- Proto/生成文件：router proto 添加 `requireRuleTag`，proxyman proto 添加 `via6`/`via6_cidr`，freedom proto 添加 `testpre`，对应 pb.go 已更新；新增路由条件/反向匹配与 ruleTag 链式匹配测试用例。

## 使用示例

- ruleTag 链式匹配与 requireRuleTag（示例包含 `+` 标记、正/反 require 以及带 outbound 与纯标记规则）：

- "+" 表示精确匹配，当规则包含requireRuleTag并且有对应tag匹配，规则才会生效，若规则不包含requireRuleTag选项，带有ruletag精确匹配的流量 将会直接跳过该规则
```json
{
  "routing": {
    "rules": [
      {
        "type": "field",
        "domain": ["geosite:google"],
        "ruleTag": "google"
      },
      {
        "type": "field",
        "domain": ["geosite:openai"],
        "ruleTag": "+openai"
      },
      {
        "type": "field",
        // this rule will continue processing tag "google", will pass tag "openai"
        // if on mode IPOnDemand, google dns result have ipv4, traffic will be routed
        "ip": ["0.0.0.0/0"],
        "outboundTag": "direct",
        "ruleTag": "ip-filter"
      },
      {
        "type": "field",
        "requireRuleTag": ["openai"],
        "outboundTag": "direct",
        "ruleTag": "final"
      },
      {
        "type": "field",
        "requireRuleTag": ["!final"],
        "outboundTag": "proxy"
      },
      {
        "type": "field",
        "requireRuleTag": ["final"],
        "outboundTag": "block"
      }
    ]
  }
}
```

- `vlessRoute` 数组快捷路由：命中即直接出站，未命中继续走规则链。
```json
{
  "routing": {
    "rules": [
      {
        "type": "field",
        "inboundTag": ["vless-in"],
        "ruleTag": "vless-fast",
        "vlessRoute": [
          "53:direct",
          "443,1000-2000:proxy"
        ]
      },
      {
        "type": "field",
        "requireRuleTag": ["vless-fast"],
        "outboundTag": "fallback"
      }
    ]
  }
}
```

- 域名/Geo 反向匹配：`geosite:!cn` 表示“非 CN”；反向与正向可混合使用。
```json
{
  "type": "field",
  "domain": ["geosite:!cn", "geosite:category-ads-all"],
  "outboundTag": "proxy"
}
```

- IP 反向匹配：以 `!` 开头写入 `ip` 列表。
```json
{
  "type": "field",
  "ip": ["!0.0.0.0/0", "10.0.0.0/8"],
  // "10.0.0.0/8" in here will not effect, "!0.0.0.0/0" includes "10.0.0.0/8"
  "outboundTag": "lan"
}
```

  - sendThrough6：需同时设置 IPv4 侧的 `sendThrough`（可为 `IPv4地址`/`IPV4/地址段`/`origin`/`srcip`），再指定 IPv6。搭配规则：
  - `sendThrough` 必须是 IPv4/`origin`/`srcip`（不可 IPv6），配置了 `sendThrough6` 时必填；


  - `sendThrough6` 只能是 IPv6 地址或 `srcip`，不支持 `origin`，`origin`请直接在`sendthrough`配置
  - 两侧都可带 CIDR，`sendThrough6` 需为 IPv6 前缀



特殊值：

  - `0.0.0.0/0` 视为未指定，与 `sendThrough6` 同用视为IPV4走默认系统出口，IPV6走指定IP。
  - `::/0` 配置在SendThrough同理，IPV6使用系统IP出口，IPV4遵循指定IP
  - `srcip` 代表着Acore会使用source ip作为源地址发起连接，需要特殊防火墙配置。这里不赘述。需要同时开启sockopt的`tproxy`
```json
{
  "outbounds": [
    {
      "protocol": "freedom",
      "sendThrough": "192.0.2.10",
      "sendThrough6": "2001:db8::114:514",
      "settings": {}
    },
    {
      "protocol": "freedom",
      "sendThrough": "192.0.2.10",
      "sendThrough6": "2001:db8::10/64",
      "settings": {}
    },
    {
      "protocol": "freedom",
      "sendThrough": "114.5.14.0/24",
      "sendThrough6": "2001:db8::10/64",
      "settings": {}
    },
    {
      "protocol": "freedom",
      "sendThrough": "srcip",
      "sendThrough6": "2001:db8::10/64",
      "streamSettings": {
        "sockopt": {
            "tproxy": "tproxy",
        },
      },
      "settings": {}
    },
    {
      "protocol": "freedom",
      "sendThrough": "0.0.0.0",
      "sendThrough6": "srcip",
      "streamSettings": {
        "sockopt": {
            "tproxy": "tproxy",
        },
      },
      "settings": {}
    },
    {
      "protocol": "freedom",
      "sendThrough": "0.0.0.0",
      "sendThrough6": "srcip",
      "streamSettings": {
        "sockopt": {
            "tproxy": "tproxy",
        },
      },
      "settings": {}
    }

  ]
}
```
- **错误示范**，orign为sendthrough时禁止设置sendThrough6
```json
{
  [
    {
      "protocol": "freedom",
      "sendThrough": "origin",
      "sendThrough6": "2001:db8::1111", //error, when sendThrough as "origin", sendthrough should not be configure
      "settings": {}
    }

  ]
}
```
- Freedom 预连接（`testpre`）：仅对设置了 `redirect` destination_override 的 freedom 生效，提前建立并复用若干连接。
```json
{
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {
        "redirect": "example.com:443",
        "testpre": 4
      }
    }
  ]
}
```
