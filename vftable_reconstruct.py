# Script by ALSchwalm, found here https://rioasmara.com/2020/08/23/ida-pro-c-vtable/

""" A simple script to locate vtable groups in binaries with the Itanium ABI.

Note that this script does not account for virtual inheritance or (more notably),
cases were the vtable contains null pointers. This may happen in more recent
compilers with purely abstract types.
"""

import idaapi
import idautils

def read_ea(ea):
    return (ea+4, idaapi.get_32bit(ea))

def read_signed_32bit(ea):
    return (ea+4, idaapi.as_signed(idaapi.get_32bit(ea), 32))

def get_table(ea):
    ''' Given an address, returns (offset_to_top, end_ea)
    for the table  located at that address or None if there
    is no table'''

    ea, offset_to_top = read_signed_32bit(ea)
    ea, rtti_ptr = read_ea(ea)
    if rtti_ptr != 0:
        return None
    func_count = 0
    while True:
        next_ea, func_ptr = read_ea(ea)
        if not func_ptr in idautils.Functions():
            break
        func_count += 1
        ea = next_ea
    if func_count == 0:
        return None
    return offset_to_top, ea

def get_table_group_bounds(ea):
    ''' Given an address, returns the (start_ea, end_ea) pair
    for the table group located at that address'''
    start_ea = ea
    prev_offset_to_top = None
    while True:
        table = get_table(ea)
        if table is None:
            break
        offset_to_top, end_ea = table
        if prev_offset_to_top is None:
            if offset_to_top != 0:
                break
            prev_offset_to_top = offset_to_top
        elif offset_to_top >= prev_offset_to_top:
            break
        ea = end_ea
    return start_ea, ea

def find_tablegroups(segname=".rodata"):
    ''' Returns a list of (start, end) ea pairs for the
    vtable groups in 'segname'
    '''
    seg = idaapi.get_segm_by_name(segname)
    ea = seg.startEA
    groups = []
    while ea < seg.endEA:
        bounds = get_table_group_bounds(ea)
        if bounds[0] == bounds[1]:
            ea += 4
            continue
        groups.append(bounds)
        ea = bounds[1]
    return groups
