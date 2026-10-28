"""Declarative stage/mode metadata, with no Tk objects or side effects."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Mode:
    code: str
    title: str
    key_count: int = 1
    text: bool = False
    iv: bool = False
    padding: bool = False


MODES = {
    "block": Mode("block", "基础分组"),
    "ascii": Mode("ascii", "ASCII 文本", text=True, padding=True),
    "double": Mode("double", "双重加密", key_count=2),
    "triple": Mode("triple", "三重加密", key_count=3),
    "cbc-blocks": Mode("cbc-blocks", "CBC 分组", iv=True),
    "cbc-text": Mode("cbc-text", "CBC 文本", text=True, iv=True),
}
STAGES = (
    ("01", "基本测试", "从一个16位分组开始，查看加解密结果与每轮变换。"),
    ("02", "交叉测试", "比较另一组的实际输出，也可运行内置独立实现对照。"),
    ("03", "ASCII 文本", "输入英文与符号，按两个字节分组，并完整还原文本。"),
    ("04", "多重加密", "分别尝试双重、三重加密，再用已知明密文寻找双重密钥。"),
    ("05", "CBC 与篡改", "共享同一个IV完成解密，观察修改密文后哪些分组发生变化。"),
)
EXAMPLES = {"block": ("0xD728", ("0x4AF5",)),
            "ascii": ("Hello S-AES!", ("0x4AF5",)),
            "double": ("0x1234", ("0x1A2B", "0x3C4D")),
            "triple": ("0x1234", ("0x1A2B", "0x3C4D", "0x5E6F")),
            "cbc-blocks": ("0x1234 0x5678 0x9ABC 0xDEF0", ("0x4AF5",)),
            "cbc-text": ("Hello CBC!", ("0x4AF5",))}
