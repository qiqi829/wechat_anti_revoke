# wechat_anti_revoke

windows版本微信消息防撤回

## 安装：

将d3d11.dll复制到微信目录的wechatwin.dll旁边。
例如：C:\Program Files\Tencent\WeChat\[4.0.6.33]

## 卸载：

删除目录下的d3d11.dll文件

## 编译：

vs2019，release，x64，生成d3d11.dll

## 原理：

未patch微信模块。
dll劫持注入拦截系统api，修改撤回消息xml数据包


