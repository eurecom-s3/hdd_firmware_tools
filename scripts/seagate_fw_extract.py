#!/usr/bin/env python

#The MIT License (MIT)
#
#Copyright (c) 2014 Jonas Zaddach <zaddach@eurecom.fr>
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

"""
    This is a tool to unpack binary blobs from the seagate firmware update file format for common seagate discs, 
    such as the Seagate Barracuda. It is meant for independent research on firmware.
"""
from collections import OrderedDict
import sys
import struct
from datetime import datetime
import hdd_crc
import argparse
import os

SIZES = {"L": 4, "H": 2}

def sizeof(struct_def):
    size = 0
    for val in map(lambda x: x[1], struct_def):
        size += SIZES[val]
        
    return size

"""
   Reverse engineered chunk structure from the firmware file.  Most fields are unknown.
   Structure definition is gives as list of tuples (field name, field size specifier as used for struct.unpack, field description (optional))"""
ARTIFACT_HEADER_DEFINITION = [("field_0", "L", "?"), 
                           ("field_4", "L", "?"),
                           ("field_8", "L", "?"), 
                           ("subtype", "H", "Section content's subtype, e.g. overlay number for overlay."),
                           ("type", "H", "Section content's type, e.g. bootloader, overlay, ..."),  
                           ("content_size", "L", "Section's content size in bytes."), 
                           ("field_14", "L", "?"),
                           ("compilation_time", "L", "Section content compilation time in ascii-hex: convert to hex string and then read hhmmMMDD"), 
                           ("compilation_date", "L", "Section content compilation date in ascii-hex: convert to hex string and then read YYYYDDMM."),
                           ("field_20", "L", "?"), 
                           ("size", "L", "Section size in bytes. Not always set, content_size is more reliable."),
                           ("field_28", "L", "?"), 
                           ("field_2C", "L", "?"),
                           ("field_30", "L", "?"), 
                           ("field_34", "L", "?"),
                           ("field_38", "L", "?"), 
                           ("field_3C", "H", "?"),
                           ("checksum_16bit", "H", "If the header is seen as shorts and summed up, the resulting sum including this field should be 0.")]
                           
SEGMENT_HEADER_DEFINITION = [("size_in_words", "L", "Size of the flash loader stub in words"),
                                ("flash_address", "L", "Address in the flash memory"),
                                ("load_address", "L", "Address where the stub should be loaded in memory"),
                                ("field_C", "L", "?")]
                                
SECTIONS_HEADER_DEFINITION = [("magic", "L", "Magic value, should be 0x44697363"),
                             ("field_14", "H", "?"),
                             ("checksum", "H", "section checksum"),
                             ("field_18", "L", "?"),
                             ("field_1C", "L", "?")]
                             
OVERLAY_HEADER_DEFINITION = [("number", "L", "Overlay number"),
                             ("id", "L", "Overlay identifier"),
                             ("size", "L", "Overlay size"),
                             ("field_C", "L", "?"),
                             ("function_string_table", "L", "Pointer to table that contains pointers to functions and strings in this overlay"),
                             ("field_14", "L", "?"),
                             ("field_18", "L", "?"),
                             ("load_address", "L", "Address where the overlay is loaded to"),
                             ("information", "L", "Pointer to various overlay information, as version, compile date, ..."),]
                             
                             

MAIN_FW_HEADER_DEFINITION = [("field_00", "L", "?"),
                             ("field_04", "L", "?"),
			     ("field_08", "L", "?"),
			     ("field_0C", "L", "?"),
			     ("field_10", "L", "?"),
			     ("field_14", "L", "?"),
			     ("field_18", "L", "?"),
			     ("field_1C", "L", "?"),
			     ("field_20", "L", "?"),
			     ("field_24", "L", "?"),
			     ("field_28", "L", "?"),
			     ("field_2C", "L", "?")]
                 
MAIN_FW_CHUNK_HEADER_DEFINITION = [("size_flags", "L" , "Size and flags as bitfield"),
                                   ("load_address", "L", "Load address in memory")]
                           
                           
ARTIFACT_OVERLAY = 0x4a
ARTIFACT_FLASH_LOADER = 0x457
ARTIFACT_BOOT_FW = 0x422
ARTIFACT_MAIN_FW = 0x426
ARTIFACT_MAYBE_BSS = 0x24
ARTIFACT_PADDING = 0x7
ARTIFACT_8051_FW = 0X9603

                           
ARTIFACT_NAMES = {ARTIFACT_OVERLAY: "Overlay", 
               ARTIFACT_BOOT_FW: "BootFW", 
               ARTIFACT_MAYBE_BSS: "MaybeBSS", 
               ARTIFACT_PADDING: "Padding",
               ARTIFACT_FLASH_LOADER: "Flash_loader_stub",
               ARTIFACT_8051_FW: "ServoController8051FW",
               ARTIFACT_MAIN_FW: "MainFW_Core",
               0x41: "?",
               0x24: "?",
               0x53: "?",
               0x4b: "?",
               0xd: "?",
               0x43: "?",
               0x442: "?"}
                           
def parse_struct(struct_definition, data, offset = 0):
    """Parse a structure according to its definition.
       TODO: Currently only parses little endian data."""
    struct_size = sizeof(struct_definition)
    struct_parse_string = "<" + "".join(map(lambda x: x[1], struct_definition))
    
    parsed_struct = struct.unpack(struct_parse_string, data[offset:offset + struct_size])
    return OrderedDict(zip(map(lambda x: x[0], struct_definition), parsed_struct))
    
    
def struct_to_string(struct_definition, struct_data):
    result = []
    for (field_name, size, description) in struct_definition:
        if size == "H":
            result.append("%s = 0x%04x" % (field_name, struct_data[field_name]))
        elif size == "L":
            result.append("%s = 0x%08x" % (field_name, struct_data[field_name]))
    return ", ".join(result)
    
def checksum_data_16bit(data):
    """Calculate 16 bit  checksum (really just summing up shorts) over a chunk."""
    return reduce(lambda r, x: (r + x) & 0xFFFF, map(lambda (x, y): (ord(y) << 8) | ord(x), zip(*[iter(data)] * 2)), 0) 
    
def parse_overlay(chunk):
    header_raw = chunk["content_raw"][:sizeof(OVERLAY_HEADER_DEFINITION)]
    header = parse_struct(OVERLAY_HEADER_DEFINITION, header_raw)
    content_raw = chunk["content_raw"][sizeof(OVERLAY_HEADER_DEFINITION):]
    
    #try some black magic to find overlay information
    
    return {"header": header, "header_raw": header_raw, "content_raw": content_raw}
    
def parse_sections(content_raw, chunk_list_heads, file_offset = None):
    chunk_lists = []
    while True:
        chunk_list = []
        chunk_list_head = struct.unpack("<L", content_raw[chunk_list_heads:chunk_list_heads+4])[0]
        chunk_list_id = chunk_list_head & 0x3f
        chunk_list_offset = chunk_list_head >> 8
        if chunk_list_id == 0:
            break
        chunk_offset = chunk_list_offset
        while True:
            chunk_header_raw = content_raw[chunk_offset:chunk_offset+8]
            if len(chunk_header_raw) != 8:
                print("ERROR: Incomplete chunk header at offset 0x%x" % (chunk_offset))
                break
            chunk_header = parse_struct(MAIN_FW_CHUNK_HEADER_DEFINITION, chunk_header_raw)
            chunk_valid = chunk_header["size_flags"] & 0x1e != 0
            chunk_size = (chunk_header["size_flags"] >> 0xc) * 4
            
            chunk_list.append({"header": chunk_header, 
                "header_raw": chunk_header_raw, 
                "content_raw": content_raw[chunk_offset+8:chunk_offset+8+chunk_size],
                "load": chunk_valid,
                "size": chunk_size,
                "offset": chunk_offset})
                
            if not file_offset is None:
                chunk_list[-1]["file_offset"] = chunk_offset + file_offset + sizeof(MAIN_FW_CHUNK_HEADER_DEFINITION)
                
            if not chunk_valid:
                break
                
            chunk_offset += 8 + chunk_size
        chunk_lists.append({"file_offset": file_offset + chunk_list_heads, "sections": chunk_list})
        chunk_list_heads += 4
    return chunk_lists
    
def parse_chunk_content(chunk):
    if chunk["header"]["type"] in [ARTIFACT_FLASH_LOADER, ARTIFACT_BOOT_FW, ARTIFACT_MAIN_FW, ARTIFACT_MAYBE_BSS]:
        segment_header_size = sizeof(SEGMENT_HEADER_DEFINITION)
        sections_header_size = sizeof(SECTIONS_HEADER_DEFINITION)
        segment_header = parse_struct(SEGMENT_HEADER_DEFINITION, chunk["content_raw"][:segment_header_size])
        segment_header["file_offset"] = chunk["file_offset"] + segment_header_size
        chunk["segment_header"] = segment_header
        sections_header = parse_struct(SECTIONS_HEADER_DEFINITION, chunk["content_raw"][segment_header_size:segment_header_size+sections_header_size])
        if sections_header["magic"] == 0x44697363:
            sections_header["file_offset"] = chunk["file_offset"] + segment_header_size+sections_header_size
            chunk["sections_header"] = sections_header
            chunk["sections"] = parse_sections(chunk["content_raw"], segment_header_size + sections_header_size, chunk["file_offset"])
    elif chunk["header"]["type"] == ARTIFACT_OVERLAY:
        data = parse_overlay(chunk)
        data["file_offset"] = chunk["file_offset"] + sizeof(OVERLAY_HEADER_DEFINITION)
        return data
    else:
        return None
                           
def load_file(filename):
    f = open(filename, "rb")
    raw_data = f.read()
    f.close()
    
    offset = 0
    chunk_index = 0
    chunks = []
    while offset < len(raw_data):
        header_raw = raw_data[offset: offset + sizeof(ARTIFACT_HEADER_DEFINITION)]
        header = parse_struct(ARTIFACT_HEADER_DEFINITION, header_raw)
        content_size = header["content_size"]
        size = content_size + sizeof(ARTIFACT_HEADER_DEFINITION)
        header_checksum_ok = checksum_data_16bit(header_raw) == 0
        content_raw = raw_data[offset + sizeof(ARTIFACT_HEADER_DEFINITION): offset + size - 4]
        crc_raw =  raw_data[offset + size - 4 : offset + size]
        crc = struct.unpack("<L", crc_raw)
        crc_ok = hdd_crc.hdd_crc16(content_raw + crc_raw) == 0
        
        
        try:
            compilation_date = header["compilation_date"]
            compilation_time = header["compilation_time"]
            del header["compilation_date"]
            #Try to format the date, if it fails we don't care
            header["compilation_date"] = datetime(int("%04x" % (compilation_date >> 16)), \
                                                    int("%02x" % (compilation_date & 0xFF)), \
                                                    int("%02x" % ((compilation_date >> 8) & 0xFF)))
            #Now try to also put the compilation time
            header["compilation_date"] = datetime(int("%04x" % (compilation_date >> 16)), \
                                                    int("%02x" % (compilation_date & 0xFF)), \
                                                    int("%02x" % ((compilation_date >> 8) & 0xFF)),
                                                    int("%02x" % ((compilation_time >> 24) & 0xFF)),
                                                    int("%02x" % ((compilation_time >> 16) & 0xFF)))
            
        except Exception, ex:
            pass
            
        chunk = {"chunk_index": chunk_index, "file_offset": offset, "header": header, "content_raw": content_raw, "content_crc": crc, \
                       "header_checksum_ok": header_checksum_ok, "content_crc_ok": crc_ok, "header_raw": header_raw, \
                       "content_crc_raw": crc_raw}
        content = parse_chunk_content(chunk)
        
        if content:
            chunk["content"] = content
            
        chunks.append(chunk)
        
        offset += size
        chunk_index += 1
        
    return chunks
#    chunk_data = raw_data[sizeof(ARTIFACT_HEADER_DEFINITION) + offset: sizeof(CHUNK_HEADER_DEFINITION) + offset + chunk_header["content_size"]) 
#    chunk_checksum = checksum_chunk_16bit(chunk_data)
#    print chunk0_header
    
    
    
    
    

def print_sections(chunk_lists):
    for chunk_list in chunk_lists:
        for mainfw_chunk in chunk_list:
            print("\tSection offset = 0x%x, size = 0x%x, load_address = 0x%x, load = %s" % \
                (mainfw_chunk["file_offset"], len(mainfw_chunk["content_raw"]), mainfw_chunk["header"]["load_address"], mainfw_chunk["load"]))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "Dump contents of Seagate firmware (.lod) files")
    parser.add_argument("--dump-sections", dest = "dump_sections", action = "store_true", default = False, help = "Dump content of each section to a binary file")
    parser.add_argument("fw_file", type = str, help = "Firmware file (.lod)")

    args = parser.parse_args()
    
    fw = load_file(args.fw_file)
    
    with open(args.fw_file, 'rb') as file:
        file_data =  file.read()
    
    for chunk in fw:
        chunk_string = "Artifact % 2d: file_offset = 0x%x, size = 0x%x, type = 0x%x (%s)" % \
            (chunk["chunk_index"], chunk["file_offset"], chunk["header"]["content_size"], chunk["header"]["type"], ARTIFACT_NAMES[chunk["header"]["type"]])

        if args.dump_sections:
            fw_filename = os.path.basename(args.fw_file)
            with open("%s_0x%08x_Artifact_%d.bin" % (fw_filename, chunk["file_offset"], chunk["chunk_index"]), 'wb') as file:
                file.write(chunk["content_raw"])

            
        if "compilation_date" in chunk["header"]:
            chunk_string += ", date = %s" % chunk["header"]["compilation_date"].__str__() 
            
        if not chunk["header_checksum_ok"]:
            chunk_string += ", header checksum wrong!"
            
        if not chunk["content_crc_ok"]:
            chunk_string += ", content checksum wrong!"
        
#        print(struct_to_string(CHUNK_HEADER_DEFINITION, parse_struct(CHUNK_HEADER_DEFINITION, chunk["header_raw"])))
        print(chunk_string)
        
        if "segment_header" in chunk:
            print("\tSegment header: file offset = 0x%x, Flash address = 0x%x, load address = 0x%x, size = 0x%x" % \
                (chunk["segment_header"]["file_offset"], chunk["segment_header"]["flash_address"], chunk["segment_header"]["load_address"], chunk["segment_header"]["size_in_words"] * 4))
            if args.dump_sections:
                segment_offset = chunk["segment_header"]["file_offset"]
                segment_size = chunk["segment_header"]["size_in_words"]  * 4
                if segment_offset + segment_size < len(file_data):
                    with open("%s_0x%08x_Segment_%d.bin" % (fw_filename, chunk["segment_header"]["file_offset"] , chunk["chunk_index"]), 'wb') as file:
                        file.write(file_data[segment_offset: segment_offset + segment_size])
                        
        if "sections_header" in chunk:
            print("\tSections header: File offset = 0x%x, magic = 0x%x, field_14 = 0x%x, checksum = 0x%x, field_18 = 0x%x, field_1C = 0x%x" % \
                (chunk["sections_header"]["file_offset"], chunk["sections_header"]["magic"], chunk["sections_header"]["field_14"], chunk["sections_header"]["checksum"], \
                 chunk["sections_header"]["field_18"], chunk["sections_header"]["field_1C"]))
            if "sections" in chunk:
                for (section_list, i) in zip(chunk["sections"], xrange(0, 1000)):
                    print("\t\tSection run %d: file offset = 0x%x" % (i, section_list["file_offset"]))
                    for (section, j) in zip(section_list["sections"], xrange(0, 1000)):
                        section_offset = section["file_offset"]
                        section_size = section["size"]
                        print("\t\t\tSection %d: file offset = 0x%x, load address = 0x%x, size = 0x%x, load = %s" % \
                            (j, section_offset, section["header"]["load_address"], section_size, section["load"]))
                        if args.dump_sections and section_size > 0:
                            with open("%s_0x%08x_Section_%d_%d.bin" % (fw_filename, section["file_offset"] , i, j), 'wb') as file:
                                file.write(file_data[section_offset: section_offset + section_size])
        if chunk["header"]["type"] == ARTIFACT_OVERLAY:
            print("\tOverlay: number = %d, id = 0x%x, size = 0x%x, load_address = 0x%x" % \
                (chunk["content"]["header"]["number"], chunk["content"]["header"]["id"], \
                 chunk["content"]["header"]["size"], chunk["content"]["header"]["load_address"])) 
            if args.dump_sections:
                with open("%s_0x%08x_Overlay_%d.bin" % (fw_filename, chunk["content"]["file_offset"], chunk["content"]["header"]["number"]), 'wb') as file:
                    file.write(file_data[chunk["content"]["file_offset"]:  chunk["content"]["file_offset"] + chunk["content"]["header"]["size"]])
    
