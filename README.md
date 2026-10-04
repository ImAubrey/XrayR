# acore-backend

[![](https://img.shields.io/badge/TgChat-@acore-backend讨论-blue.svg)](https://t.me/acore_backend_project)
[![](https://img.shields.io/badge/Channel-@acore-backend通知-blue.svg)](https://t.me/acore_backend_channel)
![](https://img.shields.io/github/stars/ImAubrey/acore-backend)
![](https://img.shields.io/github/forks/ImAubrey/acore-backend)
![](https://github.com/ImAubrey/acore-backend/actions/workflows/release.yml/badge.svg)
[![Github All Releases](https://img.shields.io/github/downloads/ImAubrey/acore-backend/total.svg)]()


[English](https://github.com/ImAubrey/acore-backend/blob/master/README-en.md)|[Iranian](https://github.com/ImAubrey/acore-backend/blob/master/README_Fa.md)|[Vietnamese](https://github.com/ImAubrey/acore-backend/blob/master/README-vi.md)

An acore backend framework that can easily support many panels.

一个基于 acore 的后端框架，支持 V2ay、Trojan、Shadowsocks 协议，极易扩展，支持多面板对接。

如果您喜欢本项目，可以右上角点个star+watch，持续关注本项目的进展。

使用教程：[详细使用教程](https://imaubrey.github.io/acore-backend-doc/)


## 免责声明

本项目只是本人个人学习开发并维护，本人不保证任何可用性，也不对使用本软件造成的任何后果负责。

## 特点

* 永久开源且免费。
* 支持V2ray，Trojan， Shadowsocks多种协议。
* 支持Vless和XTLS等新特性。
* 支持单实例对接多面板、多节点，无需重复启动。
* 支持限制在线IP
* 支持节点端口级别、用户级别限速。
* 配置简单明了。
* 修改配置自动重启实例。
* 方便编译和升级，可以快速更新核心版本，支持 acore 新特性。

## 功能介绍

| 功能        | v2ray | trojan | shadowsocks |
|-----------|-------|--------|-------------|
| 获取节点信息    | √     | √      | √           |
| 获取用户信息    | √     | √      | √           |
| 用户流量统计    | √     | √      | √           |
| 服务器信息上报   | √     | √      | √           |
| 自动申请tls证书 | √     | √      | √           |
| 自动续签tls证书 | √     | √      | √           |
| 在线人数统计    | √     | √      | √           |
| 在线用户限制    | √     | √      | √           |
| 审计规则      | √     | √      | √           |
| 节点端口限速    | √     | √      | √           |
| 按照用户限速    | √     | √      | √           |
| 自定义DNS    | √     | √      | √           |

## 支持前端

| 前端                                                     | v2ray | trojan | shadowsocks             |
|--------------------------------------------------------|-------|--------|-------------------------|
| sspanel-uim                                            | √     | √      | √ (单端口多用户和V2ray-Plugin) |
| v2board                                                | √     | √      | √                       |
| [PMPanel](https://github.com/ByteInternetHK/PMPanel)   | √     | √      | √                       |
| [ProxyPanel](https://github.com/ProxyPanel/ProxyPanel) | √     | √      | √                       |
| [WHMCS (V2RaySocks)](https://v2raysocks.doxtex.com/)   | √     | √      | √                       |
| [GoV2Panel](https://github.com/pingProMax/gov2panel)   | √     | √      | √                       |
| [BunPanel](https://github.com/pennyMorant/bunpanel-release)   | √     | √      | √                       |

## 软件安装

### 一键安装

```
wget -N https://raw.githubusercontent.com/ImAubrey/acore-backend-release/master/install.sh && bash install.sh
```

### 手动安装

[手动安装教程](https://imaubrey.github.io/acore-backend-doc/acore-backend-xia-zai-he-an-zhuang/install/manual)

## 配置文件及详细使用教程

[详细使用教程](https://imaubrey.github.io/acore-backend-doc/)

## Thanks

* [Project X](https://github.com/XTLS/)
* [V2Fly](https://github.com/v2fly)
* [VNet-V2ray](https://github.com/ProxyPanel/VNet-V2ray)
* [Air-Universe](https://github.com/crossfw/Air-Universe)

## Licence

[Mozilla Public License Version 2.0](https://github.com/ImAubrey/acore-backend/blob/master/LICENSE)

## Telgram

[acore-backend后端讨论](https://t.me/acore_backend_project)

[acore-backend通知](https://t.me/acore_backend_channel)

## Stargazers over time

[![Stargazers over time](https://starchart.cc/ImAubrey/acore-backend.svg)](https://starchart.cc/ImAubrey/acore-backend)


