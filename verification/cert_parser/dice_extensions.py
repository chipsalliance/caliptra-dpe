# Licensed under the Apache-2.0 license

from asn1crypto import core

class Fwid(core.Sequence):
    _fields = [
        ('hash_alg', core.ObjectIdentifier),
        ('digest', core.OctetString),
    ]

class FwidList(core.SequenceOf):
    _child_spec = Fwid

class IntegrityRegister(core.Sequence):
    _fields = [
        ('register_name', core.IA5String, {'tag_type': 'implicit', 'tag': 0, 'optional': True}),
        ('register_num', core.Integer, {'tag_type': 'implicit', 'tag': 1, 'optional': True}),
        ('register_digests', FwidList, {'tag_type': 'implicit', 'tag': 2}),
    ]

class IrList(core.SequenceOf):
    _child_spec = IntegrityRegister

class DiceTcbInfo(core.Sequence):
    _fields = [
        ('vendor', core.UTF8String, {'tag_type': 'implicit', 'tag': 0, 'optional': True}),
        ('model', core.UTF8String, {'tag_type': 'implicit', 'tag': 1, 'optional': True}),
        ('version', core.UTF8String, {'tag_type': 'implicit', 'tag': 2, 'optional': True}),
        ('svn', core.Integer, {'tag_type': 'implicit', 'tag': 3, 'optional': True}),
        ('layer', core.Integer, {'tag_type': 'implicit', 'tag': 4, 'optional': True}),
        ('index', core.Integer, {'tag_type': 'implicit', 'tag': 5, 'optional': True}),
        ('fwids', FwidList, {'tag_type': 'implicit', 'tag': 6, 'optional': True}),
        ('flags', core.BitString, {'tag_type': 'implicit', 'tag': 7, 'optional': True}),
        ('vendor_info', core.OctetString, {'tag_type': 'implicit', 'tag': 8, 'optional': True}),
        ('type', core.OctetString, {'tag_type': 'implicit', 'tag': 9, 'optional': True}),
        ('operational_flags_mask', core.OctetString, {'tag_type': 'implicit', 'tag': 10, 'optional': True}),
        ('integrity_registers', IrList, {'tag_type': 'implicit', 'tag': 11, 'optional': True}),
    ]

class MultiTcbInfo(core.SequenceOf):
    _child_spec = DiceTcbInfo

class TcgUeid(core.Sequence):
    _fields = [
        ('ueid', core.OctetString),
    ]

# OIDs
TCG_DICE_MULTI_TCB_INFO = '2.23.133.5.4.5'
TCG_DICE_UEID = '2.23.133.5.4.4'
