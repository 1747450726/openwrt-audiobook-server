基于OpenWRT路由器上运行的Python有声书Web服务器，支持IPv4/IPv6双栈访问

项目简介
一个专为OpenWRT路由器设计的轻量级有声书Web服务器，支持IPv4/IPv6双栈访问，具备完整的用户管理、播放进度记忆和后台监控功能。

注： 由于实在是太菜了，low到底了很多功能未实现，也懒得重构了，写的差不多了跳转也有问题，主要是给认识的人用，就想一个文件跑到黑（自行更改一下即可，记得上传下，我也想吃细糠），部分功能尚未实现（后面标记为X），后续可能会更新完善。

主要特性
 双栈网络：同时支持IPv4和IPv6访问

 域名支持：可通过域名访问

 用户系统：多用户注册，数据隔离 (X - 未实现)

 播放记忆：自动保存进度，下次自动续播

 后台管理：管理员可监控用户行为、管理用户 (X - 未实现)

 目录管理：可为用户配置私有音频目录 (X - 未实现)

 智能日志：自动轮转，防止写满存储 (X - 未实现)

 轻量化：专为OpenWRT有限资源优化

快速部署
1. 环境准备
```bash
opkg update && opkg install python3 python3-pip
```
2. 部署程序
```bash
mkdir -p /root/audiobook/data /root/audiobook/log && \
mkdir -p /mnt/mmcblk0p23/audiobooks/FRXXZ && \
chmod +x /root/audiobook/audiobook_server.py
```
3. 创建init脚本(不喜欢的可以不用)
```bash
cat > /etc/init.d/audiobook << 'EOF'
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
EOF
```
4. 启用服务
```bash
chmod +x /etc/init.d/audiobook && \
/etc/init.d/audiobook enable && \
/etc/init.d/audiobook start
```
5. 检查服务状态
```bash
/etc/init.d/audiobook status
```
使用说明
访问方式
浏览器访问：http://你的路由器IP:8000

IPv6访问：http://[IPv6地址]:8000

域名访问（如果配置了DDNS）：http://你的域名:8000

服务管理命令
```bash
# 启动服务
service audiobook start
```
```bash
# 停止服务
service audiobook stop
```
```bash
# 重启服务
service audiobook restart
```
```bash
# 查看状态
service audiobook status
```
```bash
# 查看日志
logread | grep audiobook
```

注意事项
确保OpenWRT系统已安装Python3

根据实际情况调整存储路径

防火墙需要放行8000端口

如需IPv6访问，请确认路由器IPv6配置正确

大功告成！
服务启动后，即可通过浏览器访问您的有声书服务器了。

如果有任何问题，请检查：

```bash
服务状态：service audiobook status

```
```bash
系统日志：logread | tail -50
```
```bash
端口监听：netstat -tlnp | grep 8000
```
