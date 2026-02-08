# openwrt-audiobook-server
基于OpenWRT路由器上运行的Python有声书Web服务器，支持IPv4/IPv6双栈访问
有声书Web服务器 - OpenWRT部署指南
项目简介
由于实在是太菜了，low到底了很多功能未实现，也懒得重构建了，后面为x的为未实现
一个专为OpenWRT路由器设计的轻量级有声书Web服务器，支持IPv4/IPv6双栈访问，具备完整的用户管理、播放进度记忆和后台监控功能。

主要特性
 双栈网络：同时支持IPv4和IPv6访问
 域名支持：可通过域名访问
 用户系统：多用户注册，数据隔离  X
 播放记忆：自动保存进度，下次自动续播
 后台管理：管理员可监控用户行为、管理用户  X
 目录管理：可为用户配置私有音频目录  X
 智能日志：自动轮转，防止写满存储  X\
 轻量化：专为OpenWRT有限资源优化

SS：快速开始
1. 环境准备
确保OpenWRT系统已安装Python3
opkg update
opkg install python3 python3-pip
2. 部署程序
mkdir -p /root/audiobook/{data,log}  #这个命令对于部分openwrt系统不太友好自行拆分
*.py文件需要放到/root/audiobook/  #亦可以自定义
mkdir -p /mnt/mmcblk0p23/audiobooks/FRXXZ  #亦可以自定义
chmod +x /root/audiobook/audiobook_server.py
3.设置init管理和自启，name=audiobook
#!/bin/sh /etc/rc.common

START=99
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/python3 /root/audiobook/audiobook_server.py
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

4.启用方式
chmod +x /etc/init.d/audiobook
/etc/init.d/audiobook enable
/etc/init.d/audiobook start

5.大功告成
