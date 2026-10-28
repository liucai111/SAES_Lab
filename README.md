# S-AES 实验工作台 v2

本项目对应《信息安全导论》S-AES五关实验。使用Python 3.10+与Tkinter，在本地完成加解密、交叉对照、ASCII文本、多重加密、中间相遇和CBC篡改实验，无需联网或安装运行依赖。

## 快速启动

Windows完整解压后双击start_windows.bat。也可在项目根目录打开PowerShell执行：

```powershell
python source/main.py
```

如果系统使用Python启动器，执行 `py -3 source/main.py`。Windows官方Python安装时保留Tcl/Tk组件；Ubuntu桌面缺少Tk时执行 `sudo apt install python3-tk`。不要只复制main.py，应保持source/saes目录完整。

## 新界面怎么用

左侧依次为基本测试、交叉测试、ASCII文本、多重加密、CBC与篡改。各关只显示本关所需控件；文本密文编码仅在文本解密时出现，IV只出现在CBC。

输入参数后点击“开始加密”或“开始解密”。右侧直接显示结果，点击“将密文用于解密”可自动填入下一步并保留密钥、IV及填充约定。复制结果得到可直接使用的密文或原文；保存记录才会导出JSON。执行过程默认折叠，可展开查看密钥扩展和正/逆轮状态。修改任何输入后，旧结果和相关导出按钮失效，避免误用。

第四关分开输入K1/K2/K3，不必手动拼接32或48位密钥。中间相遇独立在第四关的页签中，不要求输入真实密钥。第五关正常加密后出现篡改对比，可选择翻转密文位、替换密文分组、翻转IV位，并逐组查看差分。

## 项目目录

| 位置 | 内容 |
| --- | --- |
| source/ | 完整可运行源码、CLI、测试与复现实验脚本 |
| test_results/ | 本次自动测试日志、GUI检查、五关JSON、命令行记录、源码哈希 |
| documents/ | 测试报告、开发手册、用户指南|
| assets/ | 实际运行的新界面截图 |
| start_windows.bat | 从根目录启动桌面程序 |
| run_tests.bat | 运行算法和业务回归测试 |

## 重跑测试

在根目录运行：

```powershell
python source/run_tests.py
python source/run_experiments.py
python source/run_cli_checks.py
```

前者应为36项测试通过，后者生成五关固定数据及完整MITM候选，结果写入test_results。GUI回归需要桌面，会实际打开窗口并在结束后关闭：

```powershell
python source/run_gui_checks.py
```

应为24/24通过。截图是可选功能，只有 `--screenshots` 需要额外的Pillow；程序本身与功能测试均不需要Pillow。三份Word与原始结果相互独立，重跑程序不会自动改写Word中的时间与统计。

## 主要测试向量

| 功能 | 输入 | 密钥 | 输出 |
| --- | --- | --- | --- |
| 基础 | D728 | 4AF5 | 24EC |
| 基础 | 6F6B | A73B | 0738 |
| 双重EE | 1234 | K1=1A2B,K2=3C4D | F04D |
| 三重EEE | 1234 | 再加入K3=5E6F | 6C0F |
| CBC | 1234 5678 9ABC DEF0 | 4AF5,IV=1234 | 52B1 9936 F9DC 64ED |

GUI的Hex输入须有0x前缀，如0xD728；文本密文Hex不带0x。三重选择48 bit三密钥EEE方案。基础S-AES与课程附录D一致；教材密钥2D55扩展为2D55、BCE9、A34A。

## 本次实测与边界

36/36项自动测试、24/24项真实Tk窗口与控件回调检查、23/23项CLI验证通过，附实际界面截图。包括固定密钥全部65,536种明文、固定明文全部65,536种密钥、1,024组独立实现对照、完整MITM搜索、CBC差错传播和文件内容核对。

运行环境为Linux虚拟显示；Windows人工点击验收仍需在提交电脑完成。第二关的GUI回归使用受控测试数据，不能作为另一小组实测；外部跨小组验证需提供真实B组程序或输出，记录模板在documents。S-AES仅为小参数教学算法，CBC未提供消息认证。

提交时将本项目目录整体上传GitHub/Gitee，并按实际情况填写三位组员姓名、学号、贡献与仓库链接。
