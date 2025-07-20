#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
融合脚本：将TeleScan PE PCIE配置空间'.tlscan'文件转换为Vivado'.coe'文件和写掩码文件

用法:
    python tlscanToCoe.py <tlscan文件> <输出配置空间coe文件> <输出写掩码coe文件>

示例:
    python tlscanToCoe.py AX200.tlscan pcileech_cfgspace.coe pcileech_cfgspace_writemask.coe
    python tlscanToCoe.py ../AX200/AX200.tlscan ../AX200/pcileech_cfgspace.coe ../AX200/pcileech_cfgspace_writemask.coe
"""

import os
import sys
import datetime
import xml.etree.ElementTree as ET
import re

# 写掩码部分的常量定义
write_protected_bits_PCIE = (
    "00000000",  # 1
    "00000000",  # 2
    "ffff0000",  # 3
    "00000000",  # 4
    "ffff0000",  # 5
    "00000000",  # 6
    "00000000",  # 7
    "00000000",  # 8
    "00000000",  # 9
    "00000000",  # 10
    "ffff0000",  # 11
    "00000000",  # 12
    "00000000",  # 13
)

write_protected_bits_PM = (
    "00000000",  # 1
    "031F0000",  # 2
)

write_protected_bits_MSI_ENABLED_0 = (
    "00007104",  # 1
)

write_protected_bits_MSI_64_bit_1 = (
    "00007104",  # 1
    "03000000",  # 2
    "00000000",  # 3
    "ffff0000",  # 4
)

write_protected_bits_MSI_Multiple_Message_enabled_1 = (
    "00007104",  # 1
    "03000000",  # 2
    "00000000",  # 3
)

write_protected_bits_MSI_Multiple_Message_Capable_1 = (
    "00007104",  # 1
    "03000000",  # 2
    "00000000",  # 3
    "ffff0000",  # 4
    "00000000",  # 5
    "01000000",  # 6
)

write_protected_bits_MSIX_3 = (
    "000000c0",  # 1
    "00000000",  # 2
    "00000000",  # 3
)

write_protected_bits_MSIX_4 = (
    "000000c0",  # 1
    "00000000",  # 2
    "00000000",  # 3
    "00000000",  # 4
)

write_protected_bits_MSIX_5 = (
    "000000c0",  # 1
    "00000000",  # 2
    "00000000",  # 3
    "00000000",  # 4
    "00000000",  # 5
)

write_protected_bits_MSIX_6 = (
    "000000c0",  # 1
    "00000000",  # 2
    "00000000",  # 3
    "00000000",  # 4
    "00000000",  # 5
    "00000000",  # 6
)

write_protected_bits_MSIX_7 = (
    "000000c0",  # 1
    "00000000",  # 2
    "00000000",  # 3
    "00000000",  # 4
    "00000000",  # 5
    "00000000",  # 6
    "00000000",  # 7
)

write_protected_bits_MSIX_8 = (
    "000000c0",  # 1
    "00000000",  # 2
    "00000000",  # 3
    "00000000",  # 4
    "00000000",  # 5
    "00000000",  # 6
    "00000000",  # 7
    "00000000",  # 8
)

write_protected_bits_VPD = (
    "0000ffff",  # 1
    "ffffffff",  # 2
)

write_protected_bits_VSC = (
    "000000ff",  # 1
    "ffffffff",  # 2
)

write_protected_bits_TPH = (
    "00000000",  # 1
    "00000000",  # 2
    "070c0000",  # 3
)

write_protected_bits_VSEC = (
    "00000000",  # 1
    "00000000",  # 2
    "ffffffff",  # 3
    "ffffffff",  # 4
)

write_protected_bits_AER = (
    "00000000",  # 1
    "00000000",  # 2
    "30F0FF07",  # 3
    "30F0FF07",  # 4
    "00000000",  # 5
    "C1F10000",  # 6
    "40050000",  # 7
    "00000000",  # 8
    "00000000",  # 9
    "00000000",  # 10
    "00000000",  # 11
)

write_protected_bits_DSN = (
    "00000000",  # 1
    "00000000",  # 2
    "00000000",  # 3
)

write_protected_bits_LTR = (
    "00000000",  # 1
    "00000000",  # 2
)

write_protected_bits_L1PM = (
    "00000000",  # 1
    "00000000",  # 2
    "3f00ffe3",  # 3
    "fb000000",  # 4
)

write_protected_bits_PTM = (
    "00000000",  # 1
    "00000000",  # 2
    "00000000",  # 3
    "03ff0000",  # 4
)

write_protected_bits_VC = (
    "00000000",  # 1
    "00000000",  # 2
    "00000000",  # 3
    "0F000000",  # 4
    "00000000",  # 5
    "FF000F87",  # 6
    "00000000",  # 7
)

fixed_section = [
    "00000000", "470500f9", "00000000", "ffff0040",
    "f0ffffff", "ffffffff", "f0ffffff", "ffffffff",
    "f0ffffff", "f0ffffff", "00000000", "00000000",
    "01f8ffff", "00000000", "00000000", "ff000000",
]

CAPABILITY_NAMES = {
    0x01: "power management",
    0x02: "AGP",
    0x03: "VPD",
    0x04: "slot identification",
    0x05: "MSI",
    0x06: "compact PCI hot swap",
    0x07: "PCI-X",
    0x08: "hyper transport",
    0x09: "vendor specific",
    0x0A: "debug port",
    0x0B: "compact PCI central resource control",
    0x0C: "PCI hot plug",
    0x0D: "PCI bridge subsystem vendor ID",
    0x0E: "AGP 8x",
    0x0F: "secure device",
    0x10: "PCI express",
    0x11: "MSI-X",
    0x12: "SATA data/index configuration",
    0x13: "advanced features",
    0x14: "enhanced allocation",
    0x15: "flattening portal bridge",
}

EXTENDED_CAPABILITY_NAMES = {
    0x0001: "advanced error reporting",
    0x0002: "virtual channel",
    0x0003: "device serial number",
    0x0004: "power budgeting",
    0x0005: "root complex link declaration",
    0x0006: "root complex internal link control",
    0x0007: "root complex event collector endpoint association",
    0x0008: "multi-function virtual channel",
    0x0009: "virtual channel",
    0x000A: "root complex register block",
    0x000B: "vendor specific",
    0x000C: "configuration access correlation",
    0x000D: "access control services",
    0x000E: "alternative routing-ID interpretation",
    0x000F: "address translation services",
    0x0010: "single root IO virtualization",
    0x0011: "multi-root IO virtualization",
    0x0012: "multicast",
    0x0013: "page request interface",
    0x0014: "AMD reserved",
    0x0015: "resizable BAR",
    0x0016: "dynamic power allocation",
    0x0017: "TPH requester",
    0x0018: "latency tolerance reporting",
    0x0019: "secondary PCI express",
    0x001A: "protocol multiplexing",
    0x001B: "process address space ID",
    0x001C: "LN requester",
    0x001D: "downstream port containment",
    0x001E: "L1 PM substates",
    0x001F: "precision time measurement",
    0x0020: "M-PCIe",
    0x0021: "FRS queueing",
    0x0022: "Readyness time reporting",
    0x0023: "designated vendor specific",
    0x0024: "VF resizable BAR",
    0x0025: "data link feature",
    0x0026: "physical layer 16.0 GT/s",
    0x0027: "receiver lane margining",
    0x0028: "hierarchy ID",
    0x0029: "native PCIe enclosure management",
    0x002A: "physical layer 32.0 GT/s",
    0x002B: "alternate protocol",
    0x002C: "system firmware intermediary",
}

writemask_dict = {
    "0x10": write_protected_bits_PCIE,
    "0x03": write_protected_bits_VPD,
    "0x01": write_protected_bits_PM,
    "0x05": write_protected_bits_MSI_ENABLED_0,
    "0x05": write_protected_bits_MSI_64_bit_1,
    "0x05": write_protected_bits_MSI_Multiple_Message_Capable_1,
    "0x11": write_protected_bits_MSIX_3,
    "0x11": write_protected_bits_MSIX_4,
    "0x11": write_protected_bits_MSIX_5,
    "0x11": write_protected_bits_MSIX_6,
    "0x11": write_protected_bits_MSIX_7,
    "0x11": write_protected_bits_MSIX_8,
    "0x09": write_protected_bits_VSC,
    "0x000A": write_protected_bits_VSEC,
    "0x0001": write_protected_bits_AER,
    "0x0002": write_protected_bits_VC,
    "0x0003": write_protected_bits_DSN,
    "0x0018": write_protected_bits_LTR,
    "0x001E": write_protected_bits_L1PM,
    "0x000B": write_protected_bits_PTM,
    "0x0017": write_protected_bits_TPH,
}

def get_user_choice(cap_id):
    """根据能力ID选择合适的写掩码变体"""
    msi_choices = {
        '1': write_protected_bits_MSI_ENABLED_0,
        '2': write_protected_bits_MSI_Multiple_Message_enabled_1,
        '3': write_protected_bits_MSI_64_bit_1,
        '4': write_protected_bits_MSI_Multiple_Message_Capable_1
    }
    
    msix_choices = {
        '1': write_protected_bits_MSIX_3,
        '2': write_protected_bits_MSIX_4,
        '3': write_protected_bits_MSIX_5,
        '4': write_protected_bits_MSIX_6,
        '5': write_protected_bits_MSIX_7,
        '6': write_protected_bits_MSIX_8
    }
    
    if cap_id == 0x05:
        print("\n选择MSI写掩码变体:")
        print("1. MSI length: 1")
        print("2. MSI length: 3")
        print("3. MSI length: 4")
        print("4. MSI length: 6")
        choice = input("\n请输入选择 (1/2/3/4): ")
        return msi_choices.get(choice, write_protected_bits_MSI_ENABLED_0)
    
    if cap_id == 0x11:
        print("\n选择MSIX写掩码变体:")
        print("1. MSIX length: 3")
        print("2. MSIX length: 4")
        print("3. MSIX length: 5")
        print("4. MSIX length: 6")
        print("5. MSIX length: 7")
        print("6. MSIX length: 8")
        choice = input("\n请输入选择 (1/2/3/4/5/6): ")
        return msix_choices.get(choice, write_protected_bits_MSIX_3)
    
    return None

def read_cfg_space(dwords):
    """从DWORD列表创建配置空间字典"""
    dword_map = {}
    for i, dword in enumerate(dwords):
        dword_map[i] = dword
    return dword_map

def locate_caps(dword_map):
    """定位配置空间中的能力指针"""
    capabilities = {}
    start = (dword_map[0x34 // 4] >> 24) & 0xFF
    cap_location = start

    while cap_location != 0:
        cap_dword = dword_map[cap_location // 4]
        cap_id = (cap_dword >> 24) & 0xFF
        next_cap = (cap_dword >> 16) & 0xFF
        cap_name = CAPABILITY_NAMES.get(cap_id, "Capability Pointer")
        if cap_location == start:
            print("找到的能力:")
        print(f"{hex(cap_location):<3}: {cap_name}")
        if next_cap == 0:
            print("-" * 40)
        capabilities[f"0x{cap_id:02X}"] = cap_location
        cap_location = next_cap

    ext_cap_location = 0x100
    while ext_cap_location < len(dword_map) * 4:
        if ext_cap_location // 4 not in dword_map:
            break
            
        ext_cap_dword = dword_map[ext_cap_location // 4]
        # 转换为小端格式
        ext_cap_dword_bytes = ext_cap_dword.to_bytes(4, byteorder='little')
        ext_cap_id = int.from_bytes(ext_cap_dword_bytes[0:2], byteorder='little')
        next_ext_cap = (int.from_bytes(ext_cap_dword_bytes[2:4], byteorder='little') >> 4) & 0xFFF
        
        ext_cap_name = EXTENDED_CAPABILITY_NAMES.get(ext_cap_id, "Unknown")
        if ext_cap_location == 0x100:
            print(f"找到的扩展能力:")
            print(f"{hex(ext_cap_location):<3}: {ext_cap_name}")
        capabilities[f"0x{ext_cap_id:04X}"] = ext_cap_location
        
        if next_ext_cap == 0:
            break
        ext_cap_location = next_ext_cap

    return capabilities

def create_wrmask(dwords):
    """创建写掩码"""
    return ['ffffffff' for _ in range(len(dwords))]

def update_writemask(wr_mask, input_mask, start_index):
    """更新写掩码"""
    end_index = min(start_index + len(input_mask), len(wr_mask))
    wr_mask[start_index:end_index] = input_mask[:end_index - start_index]
    return wr_mask

def hex_string_to_int(hex_str):
    """将十六进制字符串转换为整数"""
    return int(hex_str, 16)

def create_writemask_file(dwords, output_file):
    """创建写掩码文件"""
    cfg_space = read_cfg_space(dwords)
    caps = locate_caps(cfg_space)

    wr_mask = create_wrmask(cfg_space)
    wr_mask = update_writemask(wr_mask, fixed_section, 0)

    for cap_id, cap_start in caps.items():
        section = writemask_dict.get(cap_id)
        if cap_id == "0x05" or cap_id == "0x11":
            section = get_user_choice(int(cap_id, 16))
        if section is None:
            continue
        cap_start_index = cap_start // 4
        wr_mask = update_writemask(wr_mask, section, cap_start_index)

    with open(output_file, 'w') as f:
        # f.write("; 配置空间写掩码文件\n")
        f.write("memory_initialization_radix=16;\nmemory_initialization_vector=\n\n")
        for i in range(0, len(wr_mask), 4):
            end = min(i + 4, len(wr_mask))
            f.write(','.join(wr_mask[i:end]) + ',\n')
    
    print(f"成功创建写掩码文件: {output_file}")

def main():
    """主函数"""
    # 检查命令行参数
    if len(sys.argv) < 4:
        print("用法: python tlscan2coe_combined.py <tlscan文件> <输出配置空间coe文件> <输出写掩码coe文件>")
        sys.exit(1)
    
    src_path = os.path.normpath(sys.argv[1])
    dst_coe_path = os.path.normpath(sys.argv[2])
    dst_writemask_path = os.path.normpath(sys.argv[3])
    
    try:
        # 解析XML文件
        tree = ET.parse(src_path)
        root = tree.getroot()
        
        # 获取bytes元素的文本内容
        bs_element = root.find('.//bytes')
        if bs_element is None:
            print("错误: 无法在文件中找到bytes元素")
            sys.exit(1)
        
        bs_text = bs_element.text
        
        # 移除所有空白字符
        bs = ''.join(bs_text.split())
        
        # 检查长度
        if len(bs) != 8192:
            print(f"警告: 预期8192个字符(4096个十六进制字节)，实际得到{len(bs)}个字符")
        
        # 将十六进制字符串转换为DWORD列表
        dwords = []
        for i in range(0, len(bs), 8):
            if i + 8 <= len(bs):
                # 每个DWORD是4个字节(8个十六进制字符)
                byte_str = bs[i:i+8]
                # 转换为小端格式
                dword_le = byte_str[6:8] + byte_str[4:6] + byte_str[2:4] + byte_str[0:2]
                dwords.append(hex_string_to_int(dword_le))
        
        # 写入配置空间COE文件
        with open(dst_coe_path, 'w') as fp:
            # fp.write(f"; 从\"{src_path}\"转换为COE，时间: {datetime.datetime.now()}\n")
            fp.write("memory_initialization_radix=16;\nmemory_initialization_vector=\n\n")
            
            for y in range(16):
                fp.write(f"; {(y * 256):04X}\n")
                
                for x in range(16):
                    if y * 16 + x < len(dwords) // 4:
                        idx = (y * 16 + x) * 4
                        dw1 = format(dwords[idx], '08x') if idx < len(dwords) else "00000000"
                        dw2 = format(dwords[idx+1], '08x') if idx+1 < len(dwords) else "00000000"
                        dw3 = format(dwords[idx+2], '08x') if idx+2 < len(dwords) else "00000000"
                        dw4 = format(dwords[idx+3], '08x') if idx+3 < len(dwords) else "00000000"
                        fp.write(f"{dw1},{dw2},{dw3},{dw4},\n")
            
            fp.write(";\n")
        
        print(f"成功创建配置空间文件: {dst_coe_path}")
        
        # 创建写掩码文件
        create_writemask_file(dwords, dst_writemask_path)
        
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()