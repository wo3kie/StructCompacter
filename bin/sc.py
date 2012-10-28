# Struct Compacter

import argparse
import os
import sys

from math import ceil
from fractions import gcd

# pyelftools should be installed in Python directory

#if sys.platform.startswith( 'win' ):
#    sys.path.append( '..\\3rdParty\\pyelftools-0.20' )
#elif sys.platform.startswith( 'linux' ):
#    sys.path.append( '../3rdParty/pyelftools-0.20' )
#else:
#    exit( 'Apple?' )

from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from elftools.common.py3compat import bytes2str

#
# Tests
#

def precondition( condition ):
    assert condition, str( condition )

def check( condition ):
    assert condition, str( condition )

def postcondition( condition ):
    assert condition, str( condition )

def soft_check_this_offset( this_offset, alignment ):
    if this_offset == None or alignment == None:
        return True

    return ThisOffset.validate( this_offset, alignment )

def soft_check_type_size( size ):
    if size == None:
        return True

    return TypeSize.validate( size )

#
# Utils
#

def decode( values ):
    result = 0
    for value in reversed( values ):
        result = ( result << 7 ) + ( value & 0x7F )

    return result

def abbrev( text, length ):
    precondition( length > 3 )

    if len( text ) <= length:
        result = text
    elif length <= 3:
        result = text
    else:
        result = text[0:length-3] + '...'

    postcondition( len( result ) <= length )

    return result

class ThisOffset:
    @staticmethod
    def validate( this_offset, alignment ):
        if alignment == None:
            raise TypeNotWellDefinedError( 'Alignment can not be None for offset validation' )

        if this_offset == None:
            raise TypeNotWellDefinedError( 'Offset can not be None' )

        if this_offset < 0:
            raise TypeNotWellDefinedError( 'Offset can not be <0' )

        if this_offset > 1024*1024:
            raise TypeNotWellDefinedError( 'Offset can not be >1024*1024' )

        if this_offset % alignment != 0:
            raise TypeNotWellDefinedError( \
                'Offset (%d) is not valid for alignment (%d)' % ( this_offset, alignment ) )

        return True

class TypeSize:
    @staticmethod
    def validate( size ):
        if size == None:
            raise TypeNotWellDefinedError( 'Size can not be None' )

        if size < 1:
            raise TypeNotWellDefinedError( 'Size can not be <1' )

        if size > 1024*1024:
            raise TypeNotWellDefinedError( 'Size can not be >1MB' )

        return True

class TypeName:
    @staticmethod
    def is_template( text ):
        precondition( len( text ) > 0 )

        return text.find( '<' ) != -1

    @staticmethod
    def is_stl_internal( text ):
        precondition( len( text ) > 0 )

        if text.startswith( '_' ):
            return True

        return False

    @staticmethod
    def is_vptr( text ):
        precondition( len( text ) > 0 )

        return text.startswith( '_vptr.' )

    @staticmethod
    def validate( name ):
        if name == None:
            raise TypeNotWellDefinedError( 'Type name can not be None' )

        if len( name ) == 0:
            raise TypeNotWellDefinedError( 'Type name can not be empty' )

        if len( name ) > 8*1024:
            raise TypeNotWellDefinedError( 'Type name is too long: (%s)' % name )

        # internal g++ types name begin from digits and special symbols like '.', do not validate it

        return True

#
# IVisitable
#
class IVisitable:
    def accept( self, visitor, * args ):
        visitor.visit( self, * args )

#
# Struct members representation
#
class IMember( IVisitable ):
    def __init__( self, name, type, this_offset ):
        precondition( TypeName.validate( name ) )
        precondition( type )
        precondition( soft_check_this_offset( this_offset, type.get_alignment() ) )

        self.name = name
        self.type = type
        self.this_offset = this_offset

    def get_name( self, width = None ):
        if width == None:
            return self._get_name()
        else:
            return abbrev( self._get_name(), width )

    def get_type( self ):
        return self.type

    def get_this_offset( self ):
        return self.this_offset

    def set_this_offset( self, this_offset ):
        precondition( ThisOffset.validate( this_offset, self.get_type().get_alignment() ) )

        self.this_offset = this_offset

    def get_begin( self ):
        return self.get_this_offset()

    def get_end( self ):
        return self.get_this_offset() + self.get_size()

    def get_size( self ):
        return self.type.get_size()

    def set_size( self, new_size ):
        self.type.set_size( new_size )

    def get_brief_desc( self ):
        pass

    def get_full_desc( self ):
        return self.get_brief_desc()

    # details

    def _get_name( self ):
        return self.name

class Inheritance( IMember ):
    def __init__( self, type, this_offset ):
        IMember.__init__( self, '__inheritance', type, this_offset )

    def get_brief_desc( self ):
        return self.get_name( 30 ) + ' ' \
            + self.type.get_name( 30 ) \
            + ' [this+' + str( self.this_offset ) + ']'

class EBOInheritance( IMember ):
    def __init__( self, type, this_offset ):
        IMember.__init__( self, '__ebo_inheritance', type, this_offset )

    def get_size( self ):
        return 0

    def get_brief_desc( self ):
        return self.get_name( 30 ) + ' ' \
            + self.type.get_name( 30 ) \
            + ' [this+' + str( self.this_offset ) + ']'

class Member( IMember ):
    def __init__( self, name, file_id, line_no, type, this_offset ):
        IMember.__init__( self, name, type, this_offset )

        self.file_id = file_id
        self.line_no = line_no

    def get_brief_desc( self ):
        return \
            self.get_name( 30 ) + ' ' \
            + get_desc( self.type, 30 ) \
            + ' [this+' + str( self.this_offset ) + ']'

    def get_full_desc( self ):
        return \
            self.get_name( 30 ) + ' ' \
            + ' (' + str( self.file_id ) + ':' + str( self.line_no ) + ') ' \
            + get_desc( self.type ) \
            + ' [this+' + str( self.this_offset ) + ']'

class Padding( IMember ):
    def __init__( self, type, this_offset ):
        IMember.__init__( self, '        ', type, this_offset )

    def get_brief_desc( self ):
        return self.get_name( 30 ) + ' ' \
            + self.type.get_name( 30 ) \
            + ' [this+' + str( self.this_offset ) + ']'

#
# Types representation
#
def get_desc( type, width = None ):
    prefix = '['
    suffix = ' (' + str( type.get_size() ) + ':' + str( type.get_alignment() ) + ')]'

    if width == None:
        return prefix + type.get_name() + suffix

    result = prefix + type.get_name( width - len( prefix ) - len( suffix ) ) + suffix

    postcondition( len( result ) <= width )

    return result

#
# StructCompacterError
#
class StructCompacterError( Exception ):
    def __init__( self, text ):
        Exception.__init__( self, text )

class TypeNotWellDefinedError( StructCompacterError ):
    def __init__( self, text ):
        StructCompacterError.__init__( self, text )

class EBOError( StructCompacterError ):
    def __init__( self, text ):
        StructCompacterError.__init__( self, text )


class IType( IVisitable ):
    def __init__( self, name, size ):
        precondition( TypeName.validate( name ) )
        precondition( soft_check_type_size( size ) )

        self.name = name
        self.size = size

        self.alignment = None

        self.is_valid = True

    def get_name( self, width = None ):
        if width == None:
            return self._get_name()

        result = self._decorate_name( \
                abbrev( self._get_name(), width - self._get_decoration_size() ) )

        postcondition( len( result ) <= width )

        return result

    def set_size( self, size ):
        precondition( TypeSize.validate( size ) )

        self.size = size

    def get_size( self ):
        return self.size

    def set_alignment( self, alignment ):
        precondition( Alignment.validate( alignment, self.get_size() ) )

        self.alignment = alignment

    def get_alignment( self ):
        return self.alignment

    def set_is_valid( self, is_valid ):
        self.is_valid = is_valid

    def get_is_valid( self ):
        return self.is_valid

    # details

    def _get_name( self ):
        return self.name

    def _decorate_name( self, name ):
        return name

    def _get_decoration_size( self ):
        return 0

class DeclarationType( IType ):
    def __init__( self, name ):
        IType.__init__( self, name, None )

    def _decorate_name( self, name ):
        return 'd{' + name + '}'

    def _get_decoration_size( self ):
        return 3

class UnknownType( IType ):
    def __init__( self, reason ):
        IType.__init__( self, 'Unknown', None )

        self.reason = reason

    def get_alignment( self ):
        return 1

    def get_reason( self ):
        return self.reason

class PtrType( IType ):
    def __init__( self, type, size ):
        precondition( TypeSize.validate( size ) )

        IType.__init__( self, 'Ptr', size )

        self.type = type

    def set_size( self, size ):
        raise TypeNotWellDefinedError( 'set_size is not allowed for PtrType' )

    # details

    def _get_name( self ):
        return self.type.get_name()

    def _decorate_name( self, name ):
        return name + '*'

    def _get_decoration_size( self ):
        return 1

class RefType( IType ):
    def __init__( self, type, size ):
        precondition( TypeSize.validate( size ) )

        IType.__init__( self, 'Ref', size )

        self.type = type

    def set_size( self, size ):
        raise TypeNotWellDefinedError( 'set_size is not allowed for RefType' )

    # details

    def _get_name( self ):
        return self.type.get_name()

    def _decorate_name( self, name ):
        return name + '&'

    def _get_decoration_size( self ):
        return 1

class ConstType( IType ):
    def __init__( self, type ):
        IType.__init__( self, 'Const', None )

        self.type = type

    def get_size( self ):
        return self.type.get_size()

    def set_size( self, size ):
        self.type.set_size( size )

    def get_type( self ):
        return self.type

    # details

    def _get_name( self ):
        return self.type.get_name()

    def _decorate_name( self, name ):
        return 'c{' + name + '}'

    def _get_decoration_size( self ):
        return 3

class VolatileType( IType ):
    def __init__( self, type ):
        IType.__init__( self, 'Volatile', None )

        self.type = type

    def get_size( self ):
        return self.type.get_size()

    def set_size( self, size ):
        self.type.set_size( size )

    def get_type( self ):
        return self.type

    # details

    def _get_name( self ):
        return self.type.get_name()

    def _decorate_name( self, name ):
        return 'v{' + name + '}'

    def _get_decoration_size( self ):
        return 3

class BaseType( IType ):
    def __init__( self, name, size ):
        precondition( TypeSize.validate( size ) )

        IType.__init__( self, name, size )

    def set_size( self, size ):
        raise TypeNotWellDefinedError( 'set_size is not allowed for BaseType' )

class UnionType( IType ):
    def __init__( self, name, size ):
        precondition( TypeSize.validate( size ) )

        IType.__init__( self, name, size )

    # details

    def _decorate_name( self, name ):
        return 'u{' + name + '}'

    def _get_decoration_size( self ):
        return 3

class ArrayType( IType ):
    def __init__( self, type ):
        IType.__init__( self, 'Array', None )

        self.type = type

    def get_brief_desc( self ):
        if self.get_size() == None:
            size = '?'
        else:
            size = str( self.get_size() )

        return '[' + self.get_name() + ' (' + size + ')]'

    def get_alignment( self ):
        return self.get_type().get_alignment()

    def get_type( self ):
        return self.type

    # details

    def _get_name( self ):
        return self.type._get_name()

    def _decorate_name( self, name ):
        return name + '[?]'

    def _get_decoration_size( self ):
        return 3

class StructType( IType ):
    def __init__( self, name, size ):
        precondition( TypeSize.validate( size ) )

        IType.__init__( self, name, size )

        self.is_valid = True

        self.members = []

    def get_full_desc( self ):
        total_padding = calculate_total_padding( self )
        alignment = self.get_alignment()

        result = abbrev( self.get_name(), 50 )
        result += ' ('
        result += str( self.get_size() )
        result += '/'
        result += str( total_padding )
        result += '/'
        result += str( alignment )
        result += ')'

        result += '('

        if self.get_is_valid():
            result += 'V'
        else:
            result += ' '

        if is_type_well_defined( self ):
            result += 'W'
        else:
            result += ' '

        if is_type_completely_defined( self ):
            result += 'C'
        else:
            result += ' '

        if TypeName.is_template( self.get_name() ) and is_template_param_dependent( self ):
            result += 'T'
        else:
            result += ' '

        result += ')'

        for member in self.members:
            result += '\n\t' + member.get_brief_desc()

        return result

    def add_member( self, member ):
        precondition( self._validate_member( member ) )

        self.members.append( member )

    def _validate_member( self, member ):
        # member == None
        if member == None:
            raise( TypeNotWellDefinedError( \
                'Member %s in struct %s can not be None' ) \
                    % ( member.get_name(), self.get_name() ) )

        member_begin = member.get_this_offset()

        # first member not at this+0
        if len( self.members ) == 0:
            if member_begin == 0:
                return True
            else:
                raise TypeNotWellDefinedError( \
                    'Member %s in struct %s has to be at (this+0/%d)' \
                        % ( member.get_name(), self.get_name(), member_begin ) )

        # member overlaps previous member
        #last_member_begin = self.members[ -1 ].get_this_offset()
        #
        #last_member_size = self.members[ -1 ].get_type().get_size() <- not EBOInheritance here yet
        #if last_member_size == None:
        #    last_member_size = 0
        #
        #last_member_end = last_member_begin + last_member_size
        #
        #if member_begin < last_member_end:
        #    raise TypeNotWellDefinedError( \
        #        'Member %s in struct %s lays before previous member end (this+%d/this+%d)' \
        #            % ( member.get_name(), self.get_name(), member_begin, last_member_end ) )

        # member out of a struct
        if member_begin >= self.get_size():
            raise TypeNotWellDefinedError( \
                'Member %s in struct %s is outside struct (this+%d/%d)' \
                    % ( member.get_name(), self.get_name(), member_begin, self.get_size() ) )

        return True

    def get_members( self ):
        return self.members

    def set_members( self, members ):
        del self.members[:]

        for member in members:
            self.add_member( member )

    # details

    def _decorate_name( self, name ):
        return '{' + name + '}'

    def _get_decoration_size( self ):
        return 2

class EnumType( IType ):
    def __init__( self, name, size ):
        precondition( TypeSize.validate( size ) )

        IType.__init__( self, name, size )

    # details

    def _decorate_name( self, name ):
        return 'e{' + name + '}'

    def _get_decoration_size( self ):
        return 3

class PaddingType( IType ):
    def __init__( self, size ):
        precondition( TypeSize.validate( size ) )

        IType.__init__( self, 'Padding', size )

    def get_alignment( self ):
        return 1

    # details

    def _get_name( self ):
        return 'char[' + str( self.get_size() ) + ']'


class Alignment:
    @staticmethod
    def get_from_sizeof( size ):
        precondition( size > 0 )

        return gcd( 8, size )

    @staticmethod
    def get_from_position_and_type_size( this_offset, type_size ):
        precondition( this_offset >= 0 )
        precondition( type_size > 0 )

        for i in [ 8, 4, 2, 1 ]:
            if i > type_size:
                continue

            if this_offset % i != 0:
                continue

            if type_size % i != 0:
                continue

            return i

        return 1

    @staticmethod
    def is_aligned( this_offset, alignment ):
        precondition( this_offset >= 0 )
        precondition( alignment > 0 )

        return this_offset % alignment == 0

    @staticmethod
    def get_aligned_down( value, alignment ):
        precondition( value >= 0 )
        precondition( alignment > 0 )

        return ( value // alignment ) * alignment

    @staticmethod
    def get_aligned_up( value, alignment ):
        precondition( value >= 0 )
        precondition( alignment > 0 )

        return ceil( value / alignment ) * alignment

    @staticmethod
    def validate( alignment, size ):
        if size == None:
            raise TypeNotWellDefinedError( 'Size can not be None for alignment validation' )

        if alignment == None:
            raise TypeNotWellDefinedError( 'Alignment can not be None' )

        if alignment not in [ 1, 2, 4, 8 ]:
            raise TypeNotWellDefinedError( 'Alignment (%d) is not one of [1,2,4,8]' % ( alignment ) )

        if ( size % alignment ) != 0:
            raise TypeNotWellDefinedError( \
                'Size (%d) has to be mutliplication of alignment (%d)' % ( size, alignment ) )

        return True

#
# fix_size_and_alignment
#

def try_set_alignment( type, alignment ):
    if type.get_alignment() == None or type.get_alignment() > alignment:
        type.set_alignment( alignment )

def calculate_alignment_based_on_members( struct ):
    alignment = 1

    for member in struct.get_members():
        if member.get_type().get_alignment() != None:
            alignment = max( alignment, member.get_type().get_alignment() )

    return gcd( alignment, struct.get_size() )

def fix_size_and_alignment( struct ):
    if struct.get_is_valid() == False:
        return

    members = struct.get_members()

    if len( members ) == 0:
        try_set_alignment( struct, min( struct.get_size(), 8 ) )

        return

    # resolve all but last
    for i in range( 0, len( members ) -1 ):
        member_size = members[ i + 1 ].get_this_offset() - members[ i ].get_this_offset()

        if member_size <= 0:
            members[ i ] = EBOInheritance( members[ i ].get_type(), members[ i ].get_this_offset() )

        fix_size_and_alignment_aux( members[ i ], member_size )

    # resolve last
    member_size = struct.get_size() - members[ -1 ].get_this_offset()

    if member_size <= 0:
        members[ i ] = EBOInheritance( members[ i ].get_type(), members[ i ].get_this_offset() )

    fix_size_and_alignment_aux( members[ -1 ], member_size )

    struct.set_alignment( calculate_alignment_based_on_members( struct ) )

    postcondition( Alignment.validate( struct.get_alignment(), struct.get_size() ) )

def fix_size_and_alignment_aux( member, size ):
    if member.get_type().get_size() == None:
        member.get_type().set_size( size )

    alignment \
        = Alignment.get_from_position_and_type_size( member.get_this_offset(), member.get_type().get_size() )

    try_set_alignment( member.get_type(), alignment )

#
# find_and_create_padding_members
#
def find_and_create_padding_members( struct ):
    def _create_padding( previous_member, padding_size ):
        padding_this_offset = previous_member.get_this_offset() + previous_member.get_size()
        return Padding( PaddingType( padding_size ), padding_this_offset )

    if struct.get_is_valid() == False:
        return

    members = struct.get_members()
    members_and_paddings = []

    if len( members ) == 0:
        return

    for i in range( 0, len( members ) - 1 ):
        current = members[ i ]
        next = members[ i + 1 ]

        padding_size = next.get_this_offset() - current.get_this_offset() - current.get_size()

        if padding_size < 0:
            struct.set_is_valid( False )
            raise TypeNotWellDefinedError( 'Padding size < 0 in type %s' % struct.get_name() )

        members_and_paddings.append( current )

        if padding_size > 0:
            members_and_paddings.append( _create_padding( current, padding_size ) )

    current = members[ -1 ]
    padding_size = struct.get_size() - current.get_this_offset() - current.get_size()

    if padding_size < 0:
        struct.set_is_valid( False )
        raise TypeNotWellDefinedError( 'Padding size < 0 in type %s' % struct.get_name() )

    members_and_paddings.append( current )

    if padding_size > 0:
        members_and_paddings.append( _create_padding( current, padding_size ) )

    struct.set_members( members_and_paddings )

#
# ITypeVisitor for IType hierarchy
#

def default_type_handler( visitor, type, * args ):
    return None

class ITypeVisitor:
    def __init__( self, default_handler = default_type_handler ):
        self.default_handler = default_handler

        self.dispatcher = {}

        self.dispatcher[ UnknownType ] = self.visit_unknown_type
        self.dispatcher[ DeclarationType ] = self.visit_declaration_type
        self.dispatcher[ PtrType ] = self.visit_ptr_type
        self.dispatcher[ RefType ] = self.visit_ref_type
        self.dispatcher[ ConstType ] = self.visit_const_type
        self.dispatcher[ VolatileType ] = self.visit_volatile_type
        self.dispatcher[ BaseType ] = self.visit_base_type
        self.dispatcher[ UnionType ] = self.visit_union_type
        self.dispatcher[ ArrayType ] = self.visit_array_type
        self.dispatcher[ StructType ] = self.visit_struct_type
        self.dispatcher[ EnumType ] = self.visit_enum_type
        self.dispatcher[ PaddingType ] = self.visit_padding_type

    def visit( self, interface, * args ):
        self.dispatcher[ interface.__class__ ]( interface, * args )

    def visit_unknown_type( self, unknown, * args ):
        return self.default_handler( self, unknown, * args )

    def visit_declaration_type( self, declaration, * args ):
        return self.default_handler( self, declaration, * args )

    def visit_ptr_type( self, ptr, * args ):
        return self.default_handler( self, ptr, * args )

    def visit_ref_type( self, ref, * args ):
        return self.default_handler( self, ref, * args )

    def visit_const_type( self, const, * args ):
        return self.default_handler( self, const, * args )

    def visit_volatile_type( self, volatile, * args ):
        return self.default_handler( self, volatile, * args )

    def visit_base_type( self, base, * args ):
        return self.default_handler( self, base, * args )

    def visit_union_type( self, union, * args ):
        return self.default_handler( self, union, * args )

    def visit_declaration_type( self, declaration, * args ):
        return self.default_handler( self, declaration, * args )

    def visit_array_type( self, array, * args ):
        return self.default_handler( self, array, * args )

    def visit_struct_type( self, struct, * args ):
        return self.default_handler( self, struct, * args )

    def visit_enum_type( self, enum, * args ):
        return self.default_handler( self, enum, * args )

    def visit_padding_type( self, padding, * args ):
        return self.default_handler( self, padding, * args )

#
# IMemberVisitor
#
def default_member_handler( visitor, member, * args ):
    return None

class IMemberVisitor:
    def __init__( self, default_handler = default_member_handler ):
        self.default_handler = default_handler

        self.dispatcher = {}

        self.dispatcher[ Member ] = self.visit_member
        self.dispatcher[ Inheritance ] = self.visit_inheritance
        self.dispatcher[ EBOInheritance ] = self.visit_ebo_inheritance
        self.dispatcher[ Padding ] = self.visit_padding

    def visit( self, interface, * args ):
        self.dispatcher[ interface.__class__ ]( interface, * args )

    def visit_member( self, member, * args ):
        return self.default_handler( self, member, * args )

    def visit_inheritance( self, inheritance, * args ):
        return self.default_handler( self, inheritance, * args )

    def visit_ebo_inheritance( self, ebo_inheritance, * args ):
        return self.default_handler( self, ebo_inheritance, * args )

    def visit_padding( self, padding, * args ):
        return self.default_handler( self, padding, * args )

#
# CalculateTotalPaddingVisitor
#
class CalculateTotalPaddingVisitor( IMemberVisitor ):
    def __init__( self ):
        IMemberVisitor.__init__( self )

        self.total_padding = 0

    def visit_padding( self, padding, * args ):
        self.total_padding += padding.get_type().get_size()

    def get( self ):
        return self.total_padding

def calculate_total_padding( struct ):
    members = struct.get_members()

    total_padding_visitor = CalculateTotalPaddingVisitor()

    for member in members:
        member.accept( total_padding_visitor )

    return total_padding_visitor.get()

def format_member( member, width ):
    this_offset = ' (+' + str( member.get_this_offset() ) + ')'
    this_offset_len = len( this_offset )

    name_len = ( width // 2 ) - this_offset_len
    name = member.get_name( name_len )

    type_len = ( width // 2 )
    type = get_desc( member.get_type(), type_len )

    return \
        ('{: <' + str( name_len ) + '}').format( name ) \
        + ('{: >' + str( this_offset_len ) + '}').format( this_offset ) \
        + ('{: <' + str( type_len ) + '}').format( type )

def print_struct( struct, width ):
    for member in struct.get_members():
        print( format_member( member, width ) )

def print_diff_of_structs( struct1, struct2, width ):
    struct_name = struct1.get_name()
    struct1_size = str( struct1.get_size() )
    struct2_size = str( struct2.get_size() )
    print( '{' + struct_name + '}(' + struct1_size + '/' + struct2_size + ')' )

    members_size = len( struct1.get_members() )
    compacted_size = len( struct2.get_members() )

    # member type          | member type
    for i in range( min( members_size, compacted_size ) ):
        member1 = struct1.get_members()[ i ]
        member2 = struct2.get_members()[ i ]
        print( format_member( member1, width ), '|', format_member( member2, width ) )

    if members_size == compacted_size:
        return

    empty_member_string = ( '{: <' + str( width ) + '}' ).format( '-' )

    # member type          | -
    if members_size > compacted_size:
        for i in range( compacted_size, members_size ):
            member1 = struct1.get_members()[ i ]
            print( format_member( member1, width ), '|', empty_member_string )

    # -                    | member type
    if members_size < compacted_size:
        for i in range( members_size, compacted_size ):
            member2 = struct2.get_members()[ i ]
            print( empty_member_string, '|', format_member( member2, width ) )

#
# IsTemplateParamDependentVisitor
#
class IsTemplateParamDependentVisitor( ITypeVisitor ):
    def __init__( self ):
        ITypeVisitor.__init__( self )

        self.is_dependent = False

    def visit_unknown_type( self, unknown, * args ):
        self.is_dependent = True

    def visit_declaration_type( self, declaration, * args ):
        self.is_dependent = True

    def visit_ptr_type( self, ptr, * args ):
        self.is_dependent = False

    def visit_ref_type( self, ref, * args ):
        self.is_dependent = False

    def visit_const_type( self, const, * args ):
        self.is_dependent = self.visit( const.get_type() )

    def visit_volatile_type( self, volatile, * args ):
        self.is_dependent = self.visit( volatile.get_type() )

    def visit_base_type( self, base, * args ):
        self.is_dependent = True

    def visit_union_type( self, union, * args ):
        self.is_dependent = True

    def visit_array_type( self, array, * args ):
        self.is_dependent = self.visit( array.get_type() )

    def visit_struct_type( self, struct, * args ):
        self.is_dependent = True

    def visit_enum_type( self, enum, * args ):
        self.is_dependent = False

    def visit_padding_type( self, padding, * args ):
        self.is_dependent = False

    def get( self ):
        return self.is_dependent

def is_template_param_dependent( struct ):
    visitor = IsTemplateParamDependentVisitor()

    for member in struct.get_members():
        member.get_type().accept( visitor )

        if visitor.get() == True:
            return True

    return False

#
# PrintStructVisitor
#
class PrintStructVisitor( ITypeVisitor ):
    def __init__( self ):
        ITypeVisitor.__init__( self )

    def visit_struct_type( self, struct, * args ):
        #if TypeName.is_template( struct._get_name() ):
        #    return

        #if TypeName.is_stl_internal( struct._get_name() ):
        #    return

        id = args[0]

        print( '%x %s' % ( id, struct.get_full_desc() ) )

#
# IsTypeWellDefinedVisitor
#
class IsTypeWellDefinedVisitor( ITypeVisitor ):
    def __init__( self ):
        ITypeVisitor.__init__( self )

    def visit_unknown_type( self, unknown, * args ):
        self.is_well_defined = self._visit_unknown_type_impl( unknown, * args )

    def visit_declaration_type( self, declaration, * args ):
        self.is_well_defined = self._visit_declaration_type_impl( declaration, * args )

    def visit_ptr_type( self, ptr, * args ):
        self.is_well_defined = True

    def visit_ref_type( self, ref, * args ):
        self.is_well_defined = True

    def visit_const_type( self, const, * args ):
        self.is_well_defined = is_type_well_defined( const.get_type() )

    def visit_volatile_type( self, volatile, * args ):
        self.is_well_defined = is_type_well_defined( volatile.get_type() )

    def visit_base_type( self, base, * args ):
        self.is_well_defined = True

    def visit_union_type( self, union, * args ):
        self.is_well_defined = True

    def visit_array_type( self, array, * args ):
        self.is_well_defined = is_type_well_defined( array.get_type() )

    def visit_struct_type( self, struct, * args ):
        self.is_well_defined = self._visit_struct_type_impl( struct, * args )

    def visit_enum_type( self, enum, * args ):
        self.is_well_defined = True

    def visit_padding_type( self, padding, * args ):
        self.is_well_defined = True

    def get( self ):
        return self.is_well_defined

    # details

    def _visit_unknown_type_impl( self, unknown, * args ):
        if unknown.get_size() == None:
            return False

        if unknown.get_size() <= 0:
            return False

        return True

    def _visit_declaration_type_impl( self, declaration, * args ):
        if declaration.get_size() == None:
            return False

        if declaration.get_size() <= 0:
            return False

        return True

    def _visit_struct_type_impl( self, struct, * args ):
        if struct.get_size() == None:
            return False

        if struct.get_size() == 0:
            return False

        if struct.get_alignment() == None:
            return False

        for member in struct.get_members():
            if is_type_well_defined( member.get_type() ) == False:
                return False

        return True

def is_type_well_defined( type ):
    visitor = IsTypeWellDefinedVisitor()

    type.accept( visitor )

    return visitor.get()

#
# IsTypeWellDefinedVisitor
#
class IsTypeCompletelyDefinedVisitor( ITypeVisitor ):
    def __init__( self ):
        ITypeVisitor.__init__( self )

    def visit_unknown_type( self, unknown, * args ):
        self.is_completely_defined = False

    def visit_declaration_type( self, declaration, * args ):
        self.is_completely_defined = False

    def visit_ptr_type( self, ptr, * args ):
        self.is_completely_defined = True

    def visit_ref_type( self, ref, * args ):
        self.is_completely_defined = True

    def visit_const_type( self, const, * args ):
        self.is_completely_defined = is_type_completely_defined( const.get_type() )

    def visit_volatile_type( self, volatile, * args ):
        self.is_completely_defined = is_type_completely_defined( volatile.get_type() )

    def visit_base_type( self, base, * args ):
        self.is_completely_defined = True

    def visit_union_type( self, union, * args ):
        self.is_completely_defined = True

    def visit_array_type( self, array, * args ):
        self.is_completely_defined = is_type_completely_defined( array.get_type() )

    def visit_struct_type( self, struct, * args ):
        self.is_completely_defined = self._visit_struct_type_impl( struct, * args )

    def visit_enum_type( self, enum, * args ):
        self.is_completely_defined = True

    def visit_padding_type( self, padding, * args ):
        self.is_completely_defined = True

    def get( self ):
        return self.is_completely_defined

    # details

    def _visit_struct_type_impl( self, struct, * args ):
        for member in struct.get_members():
            if is_type_completely_defined( member.get_type() ) == False:
                return False

        return True

def is_type_completely_defined( type ):
    visitor = IsTypeCompletelyDefinedVisitor()

    type.accept( visitor )

    return visitor.get()

#
# INode
#
class INode( IMember ):
    def __init__( self, name, type, this_offset ):
        IMember.__init__( self, name, type, this_offset )

        self.next = None
        self.prev = None

class HeadNode( INode ):
    def __init__( self ):
        INode.__init__( self, 'Head', UnknownType( 'HeadNode' ), None )

    def get_this_offset( self ):
        return 0

    def get_size( self ):
        return 0

    def __str__( self ):
        return 'Head'

class EndNode( INode ):
    def __init__( self ):
        INode.__init__( self, 'End', UnknownType( 'EndNode' ), None )

    def get_this_offset( self ):
        return 0

    def get_size( self ):
        return 0

    def __str__( self ):
        return 'End'

class InheritanceNode( INode ):
    def __init__( self, type, this_offset ):
        INode.__init__( self, '__inheritance', type, this_offset )

    def __str__( self ):
        return 'Inheritance ' + get_desc( self.type )

class EBOInheritanceNode( INode ):
    def __init__( self, type, this_offset ):
        INode.__init__( self, '__ebo_inheritance', type, this_offset )

    def get_size( self ):
        return 0

    def __str__( self ):
        return 'EBOInheritance ' + get_desc( self.type )

class MemberNode( INode ):
    def __init__( self, name, type, this_offset ):
        INode.__init__( self, name, type, this_offset )

    def __str__( self ):
        return self.get_name() + ' ' + self.get_type().get_name() \
            + ' (' + str( self.get_size() ) + ')' \
            + ' +(' + str( self.get_this_offset() ) + ')'

class PaddingNode( INode ):
    def __init__( self, type, this_offset ):
        INode.__init__( self, '__padding', type, this_offset )

    def set_size( self, size ):
        precondition( TypeSize.validate( size ) )

        self.get_type().set_size( size )

    def __str__( self ):
        return '__padding [' + str( self.get_size() ) + ']'\
            ' +(' + str( self.get_this_offset() ) + ')'

#
# INodeVisitor
#
def default_node_handler( self, node, * args ):
    return None

class INodeVisitor:
    def __init__( self, default_handler = default_node_handler ):
        self.default_handler = default_handler

        self.dispatcher = {}

        self.dispatcher[ HeadNode ] = self.visit_head_node
        self.dispatcher[ MemberNode ] = self.visit_member_node
        self.dispatcher[ InheritanceNode ] = self.visit_inheritance_node
        self.dispatcher[ EBOInheritanceNode ] = self.visit_ebo_inheritance_node
        self.dispatcher[ PaddingNode ] = self.visit_padding_node

    def visit( self, node, * args ):
        self.dispatcher[ node.__class__ ]( node, * args )

    def visit_head_node( self, head, * args ):
        return self.default_handler( self, head, * args )

    def visit_member_node( self, member, * args ):
        return self.default_handler( self, member, * args )

    def visit_inheritance_node( self, inheritance, * args ):
        return self.default_handler( self, inheritance, * args )

    def visit_ebo_inheritance_node( self, inheritance, * args ):
        return self.default_handler( self, inheritance, * args )

    def visit_padding_node( self, padding, * args ):
        return self.default_handler( self, padding, * args )

#
# TypesToNodesConversionVisitor
#
class TypesToNodesConversionVisitor( IMemberVisitor ):
    def __init__( self ):
        IMemberVisitor.__init__( self )

        self.node = None

    def visit_inheritance( self, inheritance, * args ):
        self.node = InheritanceNode( inheritance.get_type(), None )

    def visit_ebo_inheritance( self, ebo_inheritance, * args ):
        self.node = EBOInheritanceNode( ebo_inheritance.get_type(), None )

    def visit_member( self, member, * args ):
        self.node = MemberNode( member.get_name(), member.get_type(), None )

    def visit_padding( self, padding, * args ):
        self.node = PaddingNode( PaddingType( padding.get_size() ), None )

    def get_node( self ):
        return self.node

#
# FindMatchingPaddingVisitor
#
def check_padding( padding, size, alignment ):
    precondition( TypeSize.validate( size ) )
    precondition( Alignment.validate( alignment, size ) )

    if padding.get_size() < size:
        return False

    padding_this = padding.get_this_offset()
    padding_this_aligned = Alignment.get_aligned_up( padding_this, alignment )

    return ( padding.get_size() - ( padding_this_aligned - padding_this ) ) >= size

#
# Struct members representation
#
class FindMatchingPaddingVisitor( INodeVisitor ):
    def __init__( self, size, alignment ):
        INodeVisitor.__init__( self )

        self.size = size
        self.alignment = alignment

        self.padding = None

    def visit_padding_node( self, padding, * args ):
        if check_padding( padding, self.size, self.alignment ):
            self.padding = padding

    def get( self ):
        return self.padding

class NodeToTypeConversionVisitor( INodeVisitor ):
    def __init__( self ):
        INodeVisitor.__init__( self )

        self.type = None

    def visit_padding_node( self, padding, * args ):
        self.type = Padding( PaddingType( padding.get_size() ), padding.get_this_offset() )

    def visit_member_node( self, member, * args ):
        name = member.get_name()
        type = member.get_type()
        this_offset = member.get_this_offset()

        self.type = Member( name, None, None, type, this_offset )

    def visit_inheritance_node( self, inheritance, * args ):
        self.type = Inheritance( inheritance.get_type(), inheritance.get_this_offset() )

    def visit_ebo_inheritance_node( self, ebo_inheritance, * args ):
        self.type = EBOInheritance( ebo_inheritance.get_type(), ebo_inheritance.get_this_offset() )

    def get_type( self ):
        return self.type

#
# MemberList
#
class MemberList:
    def __init__( self ):
        self.members_front = HeadNode()
        self.members_back = self.members_front

    def print( self ):
        head = self.members_front

        while head:
            print( str( head ) )
            head = head.next

        print( '\n' )

    def front( self ):
        return self.members_front

    def back( self ):
        return self.members_back

    def append( self, node ):
        node.prev = self.members_back
        self.members_back.next = node

        self.members_back = node

    def pop_back( self ):
        self.members_back = self.members_back.prev
        self.members_back.next.prev = None
        self.members_back.next = None

    def erase( self, node ):
        if self.members_back == node:
            self.pop_back()
            return None

        node.prev.next = node.next
        node.next.prev = node.prev

        result = node.next

        node.prev = None
        node.next = None

        return result

    def insert( self, pos, node ):
        if self.members_back == pos:
            self.append( node )
        else:
            node.next = pos.next
            node.next.prev = node

            node.prev = pos
            pos.next = node

#
# StructCompacter
#
class StructCompacter:
    def __init__( self ):
        self.type_to_node_conversion_visitor = TypesToNodesConversionVisitor()

        self.members = MemberList()
        self._init_dispatcher()
        self.struct = None

    def process( self, struct ):
        #if is_type_well_defined( struct ) == False:
        #    return None

        if struct.get_is_valid() == False:
            return None

        if calculate_total_padding( struct ) < struct.get_alignment():
            return None

        self.struct = struct

        try:
            self._pack_members()

            packed_struct_size = self.members.back().get_end()

            if struct.get_size() == packed_struct_size:
                return None

            result = StructType( struct.get_name(), packed_struct_size )
            try_set_alignment( result, struct.get_alignment() )
            result.set_members( StructCompacter._convert_nodes_to_members( self.members.front().next ) )

            return result

        except EBOError as error:
            if self.config.warnings:
                print( 'Warning:', error )

            return None

    def dispatch( self, object1, object2 ):
        self.dispatcher[ ( object1.__class__, object2.__class__ ) ]( object1, object2 )

    #
    # conversions between external and internal data structures
    #

    @staticmethod
    def _convert_from_node( node ):
        node_to_type_conversion_visitor = NodeToTypeConversionVisitor()

        node.accept( node_to_type_conversion_visitor )
        return node_to_type_conversion_visitor.get_type()

    @staticmethod
    def _convert_nodes_to_members( node ):
        members = []

        while node:
            members.append( StructCompacter._convert_from_node( node ) )
            node = node.next

        return members

    def _convert_to_node( self, member ):
        member.accept( self.type_to_node_conversion_visitor )
        return self.type_to_node_conversion_visitor.get_node()

    #
    # callbacks
    #

    def _init_dispatcher( self ):
        self.dispatcher = {}

        self.dispatcher[ ( HeadNode, InheritanceNode ) ] = self._process_head_inheritance
        self.dispatcher[ ( HeadNode, EBOInheritanceNode ) ] = self._process_head_ebo_inheritance
        self.dispatcher[ ( HeadNode, MemberNode ) ] = self._process_head_member
        self.dispatcher[ ( HeadNode, PaddingNode ) ] = self._process_head_padding

        self.dispatcher[ ( InheritanceNode, InheritanceNode ) ] = self._process_inheritance_inheritance
        self.dispatcher[ ( InheritanceNode, MemberNode ) ] = self._process_inheritance_member
        self.dispatcher[ ( InheritanceNode, PaddingNode ) ] = self._process_inheritance_padding

        self.dispatcher[ ( EBOInheritanceNode, InheritanceNode ) ] = self._process_ebo_inheritance_inheritance
        self.dispatcher[ ( EBOInheritanceNode, EBOInheritanceNode ) ] = self._process_ebo_inheritance_ebo_inheritance
        self.dispatcher[ ( EBOInheritanceNode, MemberNode ) ] = self._process_ebo_inheritance_member
        self.dispatcher[ ( EBOInheritanceNode, PaddingNode ) ] = self._process_ebo_inheritance_padding

        self.dispatcher[ ( MemberNode, MemberNode ) ] = self._process_member_member
        self.dispatcher[ ( MemberNode, PaddingNode ) ] = self._process_member_padding

        self.dispatcher[ ( PaddingNode, MemberNode ) ] = self._process_padding_member
        self.dispatcher[ ( PaddingNode, PaddingNode ) ] = self._process_padding_padding

        self.dispatcher[ ( InheritanceNode, EndNode ) ] = self._process_inheritance_end
        self.dispatcher[ ( EBOInheritanceNode, EndNode ) ] = self._process_ebo_inheritance_end
        self.dispatcher[ ( MemberNode, EndNode ) ] = self._process_member_end
        self.dispatcher[ ( PaddingNode, EndNode ) ] = self._process_padding_end

    def _process_head_ebo_inheritance( self, tail, ebo_inheritance ):
        ebo_inheritance.set_this_offset( 0 )
        self.members.append( ebo_inheritance )

    def _process_ebo_inheritance_inheritance( self, tail, inheritance ):
        inheritance.set_this_offset( tail.get_end() )
        self.members.append( ebo_inheritance )

    def _process_ebo_inheritance_ebo_inheritance( self, tail, ebo_inheritance ):
        ebo_inheritance.set_this_offset( tail.get_end() )
        self.members.append( ebo_inheritance )

    def _process_ebo_inheritance_member( self, tail, member ):
        self._add_unaligned_member( member )

    def _process_ebo_inheritance_padding( self, tail, padding ):
        self._add_unaligned_member( padding )

    def _process_ebo_inheritance_end( self, tail, end ):
        self._add_back_padding()

    def _process_inheritance_end( self, tail, end ):
        self._add_back_padding()

    def _add_back_padding( self ):
        struct_end = self.members.back().get_end()
        aligned_struct_end = Alignment.get_aligned_up( struct_end, self.struct.get_alignment() )

        back_padding_size = aligned_struct_end - struct_end

        if back_padding_size == 0:
            return

        back_padding = PaddingNode( PaddingType( back_padding_size ), struct_end )
        self.members.append( back_padding )

    def _process_member_end( self, tail, end ):
        self._add_back_padding()

    def _process_padding_end( self, tail, end ):
        back_padding_this_offset = tail.get_this_offset()
        aligned_struct_end \
            = Alignment.get_aligned_up( back_padding_this_offset, self.struct.get_alignment() )

        back_padding_new_size = aligned_struct_end - back_padding_this_offset
        back_padding_new_size = back_padding_new_size % self.struct.get_alignment()

        if back_padding_new_size == 0:
            self.members.pop_back()
        elif tail.get_size() != back_padding_new_size:
            tail.get_type().set_size( back_padding_new_size )

    def _process_padding_padding( self, tail, padding ):
        total_padding_size = tail.get_size() + padding.get_size()
        total_padding_size = total_padding_size % self.struct.get_alignment()

        if total_padding_size == 0:
            self.members.pop_back()
        elif tail.get_size() != total_padding_size:
            tail.get_type().set_size( total_padding_size )

    def _process_padding_member( self, tail, member ):
        member_size = member.get_size()
        member_alignment = member.get_type().get_alignment()

        found_padding \
            = StructCompacter._find_matching_padding( self.members.front(), member_size, member_alignment )

        if found_padding != None:
            self._move_member_into_padding( found_padding, member )
        elif self._try_shrink_padding_right( tail, member ):
            return
        else:
            self._add_unaligned_member( member )

    def _process_member_padding( self, tail, padding ):
        padding.set_this_offset( self._get_aligned_struct_size( padding.get_type().get_alignment() ) )
        self.members.append( padding )

    def _process_member_member( self, tail, member ):
        member_size = member.get_size()
        member_alignment = member.get_type().get_alignment()
        padding_node = self._find_matching_padding( self.members.front(), member_size, member_alignment )

        if padding_node == None:
            self._add_unaligned_member( member )
        else:
            self._move_member_into_padding( padding_node, member )

    def _process_inheritance_padding( self, tail, padding ):
        padding.set_this_offset( self._get_aligned_struct_size( padding.get_type().get_alignment() ) )
        self.members.append( padding )

    def _process_inheritance_inheritance( self, tail, inheritance ):
        self._add_unaligned_member( inheritance )

    def _process_inheritance_member( self, tail, member ):
        self._add_unaligned_member( member )

    def _process_head_inheritance( self, tail, inheritance ):
        inheritance.set_this_offset( 0 )
        self.members.append( inheritance )

    def _process_head_member( self, tail, member ):
        member.set_this_offset( 0 )
        self.members.append( member )

    def _process_head_padding( self, tail, padding ):
        padding.set_this_offset( 0 )
        self.members.append( padding )

    #
    # details
    #

    def _pack_members( self ):
        for member in self.struct.get_members():
            tail = self.members.back()
            node = self._convert_to_node( member )

            self.dispatch( tail, node )

            #self.members.print()

        self.dispatch( self.members.back(), EndNode() )

    def _try_shrink_padding_right( self, padding, member ):
        if Alignment.is_aligned( padding.get_this_offset(), member.get_type().get_alignment() ):
            self.members.pop_back()
        elif padding.get_size() < member.get_type().get_alignment():
            return False
        else:
            padding.get_type().set_size( padding.get_size() % member.get_type().get_alignment() )

        self._add_unaligned_member( member )

        return True

    def _get_aligned_struct_size( self, alignment ):
        struct_size = self.members.back().get_end()
        aligned_struct_size = Alignment.get_aligned_up( struct_size, alignment )

        return aligned_struct_size

    def _add_unaligned_member( self, member ):
        member.set_this_offset( self._get_aligned_struct_size( member.get_type().get_alignment() ) )

        alignment_padding = self._get_alignment_padding( member )

        if alignment_padding:
            self.dispatch( self.members.back(), alignment_padding )

        self.members.append( member )

    def _get_alignment_padding( self, member ):
        struct_end = self.members.back().get_end()
        alignment_padding_size = member.get_this_offset() - struct_end

        if alignment_padding_size == 0:
            return None

        padding_type = PaddingType( alignment_padding_size )
        return PaddingNode( padding_type, struct_end )

    def _move_member_into_padding( self, padding, member ):
        if padding.get_size() == member.get_size():
            self._move_member_into_exact_match_padding( padding, member )
        else:
            self._move_member_into_not_exact_match_padding( padding, member )

    def _move_member_into_exact_match_padding( self, padding, member ):
        member.set_this_offset( padding.get_this_offset() )

        self.members.insert( padding, member )
        self.members.erase( padding )

    def _move_member_into_not_exact_match_padding( self, padding, member ):
        member_new_this_offset \
            = Alignment.get_aligned_up( padding.get_this_offset(), member.get_type().get_alignment() )

        front_padding_this_offset = padding.get_this_offset()
        front_padding_size = member_new_this_offset - front_padding_this_offset

        back_padding_this_offset = member_new_this_offset + member.get_size()
        right_padding_size \
            = ( padding.get_this_offset() + padding.get_size() ) \
            - ( member_new_this_offset + member.get_size() )

        member.set_this_offset( member_new_this_offset )

        if front_padding_size != 0 and right_padding_size != 0:
            padding.set_size( member_new_this_offset - padding.this_offset )

            new_padding = PaddingNode( PaddingType( right_padding_size ), back_padding_this_offset )

            self.members.insert( padding, member )
            self.members.insert( member, new_padding )

        elif front_padding_size != 0:
            padding.set_size( front_padding_size )

            self.members.insert( padding, member )

        elif right_padding_size != 0:
            padding.set_size( right_padding_size )
            padding.set_this_offset( padding.get_this_offset() + member.get_size() )

            self.members.insert( padding.prev, member )

    @staticmethod
    def _find_matching_padding( head, size, alignment ):
        visitor = FindMatchingPaddingVisitor( size, alignment )

        while head:
            head.accept( visitor )

            if visitor.get():
                return visitor.get()

            head = head.next

        return None

#
# FixSizeAlignmentVisitor
#
class FixSizeAlignmentVisitor( ITypeVisitor ):
    def __init__( self ):
        ITypeVisitor.__init__( self )

    def visit_struct_type( self, struct, * args ):
        fix_size_and_alignment( struct )

#
# DetectPaddingVisitor
#
class DetectPaddingVisitor( ITypeVisitor ):
    def __init__( self ):
        ITypeVisitor.__init__( self )

    def visit_struct_type( self, struct, * args ):
        find_and_create_padding_members( struct )

#
# CompactStructVisitor
#
class CompactStructVisitor( ITypeVisitor ):
    def __init__( self ):
        ITypeVisitor.__init__( self )

        self.packed = None

    def visit_struct_type( self, struct, * args ):
        if self._skip_type( struct ):
            self.packed = None
        else:
            self.packed = StructCompacter().process( struct )

    def get_and_clear( self ):
        result = self.packed
        self.packed = None

        return result

    def clear( self ):
        self.packed = None

    # details

    def _skip_type( self, struct ):
        if TypeName.is_stl_internal( struct.get_name() ):
            return True

        if TypeName.is_template( struct.get_name() ):
            if is_template_param_dependent( struct ):
                return True

        return False

#
# Utils for DIE
#
class DIE:
    @staticmethod
    def is_struct( die ):
        return die.tag in ( 'DW_TAG_class_type', 'DW_TAG_structure_type' )

    @staticmethod
    def is_static( die ):
        return 'DW_AT_external' in die.attributes

    @staticmethod
    def is_member( die ):
        if die.tag != 'DW_TAG_member':
            return False
        elif DIE.is_static( die ):
            return False
        else:
            return True

    @staticmethod
    def get_name( die, dies ):
        try:
            return DIE._get_name_impl( die )
        except KeyError:
            pass

        try:
            return DIE._get_name_from_specification( die, dies )
        except KeyError:
            pass

        return 'anonymous'

    @staticmethod
    def get_size( die ):
        try:
            return die.attributes[ 'DW_AT_size' ].value
        except KeyError:
            pass

        try:
            return die.attributes[ 'DW_AT_byte_size' ].value
        except KeyError:
            pass

        return None

    @staticmethod
    def get_file_id( die ):
        try:
            return die.attributes[ 'DW_AT_decl_file' ].value
        except KeyError:
            return -1

    @staticmethod
    def get_line_number( die ):
        if 'DW_AT_decl_line' in die.attributes:
            return die.attributes[ 'DW_AT_decl_line' ].value
        else:
            return -1

    @staticmethod
    def get_type_id( die, dies ):
        try:
            return die.attributes[ 'DW_AT_type' ].value
        except KeyError:
            pass

        try:
            DIE._get_type_id_from_specification( die, dies )
        except KeyError:
            pass

        return None

    @staticmethod
    def get_this_offset( die ):
        attr = die.attributes[ 'DW_AT_data_member_location' ]
        return decode( attr.value[1:] )

    @staticmethod
    def is_template( die, dies ):
        return TypeName.is_template( DIE.get_name( die, dies ) )

    @staticmethod
    def is_stl( die, dies ):
        return TypeName.is_stl_internal( DIE.get_name( die, dies ) )

    @staticmethod
    def is_local_type( die ):
        # todo
        return False

    @staticmethod
    def is_inheritance( die ):
        return die.tag == 'DW_TAG_inheritance'

    @staticmethod
    def is_declaration( die ):
        return 'DW_AT_declaration' in die.attributes

    # details

    @staticmethod
    def _get_name_impl( die ):
        return die.attributes[ 'DW_AT_name' ].value.decode( 'utf-8' )

    @staticmethod
    def _get_name_from_specification( die, dies ):
        specification_id = die.attributes[ 'DW_AT_specification' ].value
        specification_die = dies[ specification_id ]
        result = DIE.get_name( specification_die, dies )

        return result

    @staticmethod
    def _get_type_id_from_specification( die, dies ):
        specification_id = die.attributes[ 'DW_AT_specification' ].value
        specification_die = dies[ specification_id ]
        result = DIE.get_type_id( specification_die )

        return result

#
# DIEReader from DWARF/DIEs into abstract representation of types
#
class DIEReader:
    def __init__( self, config ):
        self.config = config

        self.dies = {}
        self.types = {}

        self.ptr_size = None
        self.ref_size = None

    def process( self, dwarf_info ):
        self.ptr_size = self._get_ptr_size( dwarf_info )
        self.ref_size = self.ptr_size

        self._make_dies_mapping( dwarf_info )
        self._convert_die_to_structs( dwarf_info )

        return self.types

    def get_types( self ):
        return self.types

    # details

    def _get_ptr_size( self, dwarf_info ):
        for cu in dwarf_info.iter_CUs():
            return cu[ 'address_size' ]

    def _create_type( self, die ):
        type = self._resolve_type( die )
        self.types[ die.offset ] = type
        return type

    def _get_or_create_type( self, die ):
        if die.offset in self.types:
            return self.types[ die.offset ]
        else:
            return self._create_type( die )

    def _resolve_type( self, die ):
        if die.offset in self.types:
            return self.types[ die.offset ]
        else:
            return self._resolve_type_impl( die )

    def _cache( self, offset, type ):
        self.types[ offset ] = type
        return type

    def _resolve_type_impl( self, die ):

        # process simple types

        name = DIE.get_name( die, self.dies )
        size = DIE.get_size( die )

        if die.tag == 'DW_TAG_class_type' or die.tag == 'DW_TAG_structure_type':
            return self._convert_die_to_struct( die )

        # cache type
        if die.tag == 'DW_TAG_base_type':
            return self._cache( die.offset, BaseType( name, size ) )
        elif die.tag == 'DW_TAG_union_type':
            return self._cache( die.offset, UnionType( name, size ) )
        elif die.tag == 'DW_TAG_enumeration_type':
            return self._cache( die.offset, EnumType( name, size ) )

        # process derived types

        type_id = DIE.get_type_id( die, self.dies )

        if type_id == None:
            type = UnknownType( 'type_id is None' )
        else:
            type = self._get_or_create_type( self.dies[ type_id ] )

        # do not cache type
        if die.tag == 'DW_TAG_member':
            return type
        elif die.tag == 'DW_TAG_inheritance':
            return type
        elif die.tag == 'DW_TAG_typedef':
            return type
        elif die.tag == 'DW_TAG_array_type':
            return ArrayType( type )

        # cache type
        if die.tag == 'DW_TAG_pointer_type':
            return self._cache( die.offset, PtrType( type, self.ptr_size ) )
        elif die.tag == 'DW_TAG_reference_type':
            return self._cache( die.offset, RefType( type, self.ref_size ) )
        elif die.tag == 'DW_TAG_const_type':
            return self._cache( die.offset, ConstType( type ) )
        elif die.tag == 'DW_TAG_volatile_type':
            return self._cache( die.offset, VolatileType( type ) )

        return UnknownType( 'Wrong die.tag %s' % die.tag )

    def _resolve_member_type( self, die ):
        type_id = DIE.get_type_id( die, self.dies )

        if type_id == None:
            return UnknownType( 'type_id is None' )
        else:
            return self._resolve_type( self.dies[ type_id ] )

    def _convert_die_to_member( self, die ):
        assert DIE.is_member( die ), 'die has to be a member'

        name = DIE.get_name( die, self.dies )
        file_id = DIE.get_file_id( die );
        line_no = DIE.get_line_number( die )
        type = self._resolve_member_type( die )
        this_offset = DIE.get_this_offset( die )

        return Member( name, file_id, line_no, type, this_offset )

    def _convert_die_to_inheritance( self, die ):
        assert DIE.is_inheritance( die ), 'die has to be a inheritance'

        type = self._resolve_member_type( die )
        this_offset = DIE.get_this_offset( die )

        return Inheritance( type, this_offset )

    def _create_struct_or_declaration( self, die ):
        size = DIE.get_size( die )
        name = DIE.get_name( die, self.dies )
        is_declaration = DIE.is_declaration( die )

        if is_declaration or size == None:
            return DeclarationType( name )

        struct = StructType( name, size )
        return self._cache( die.offset, struct )

    def _convert_die_to_struct( self, die ):
        assert DIE.is_struct( die ), 'die has to be a struct %s' % die.tag

        try:
            return self.types[ die.offset ]
        except KeyError:
            struct = self._create_struct_or_declaration( die )

        try:
            for child in die.iter_children():
                if DIE.is_inheritance( child ):
                    struct.add_member( self._convert_die_to_inheritance( child ) )
                elif DIE.is_member( child ):
                    struct.add_member( self._convert_die_to_member( child ) )
                elif DIE.is_struct( child ):
                    self._convert_die_to_struct( child )
        except StructCompacterError as error:
            if self.config.warnings:
                print( 'Warning: ', error )

        return struct

    def _make_dies_mapping_recursively( self, die ):
        self.dies[ die.offset ] = die

        for children in die.iter_children():
            self._make_dies_mapping_recursively( children )

    def _convert_die_to_structs_recursively( self, die ):
        if DIE.is_struct( die ):
            self._convert_die_to_struct( die )

        for children in die.iter_children():
            self._convert_die_to_structs_recursively( children )

    def _make_dies_mapping( self, dwarf_info ):
        for cu in dwarf_info.iter_CUs():
            top_die = cu.get_top_DIE()

            self._make_dies_mapping_recursively( top_die )

    def _convert_die_to_structs( self, dwarf_info ):
        for cu in dwarf_info.iter_CUs():
            top_die = cu.get_top_DIE()

            self._convert_die_to_structs_recursively( top_die )

#
# Application
#
class Application:
    def __init__( self, config ):
        self.config = config

        self.dies = {}
        self.die_reader = DIEReader( config )

    def process( self, file_name ):
        try:
            print( 'Reading DWARF (may take some time)...' )
            types = self._read_DWARF( file_name )

            print( 'Fixing types...' )
            types = self._fix_types( types )

            print( 'Finding paddings...' )
            types = self._detect_padding( types )

            if self.config.verbose:
                self._print_structs( types )

            print( 'Compacting structs...' )
            packed_types = self._compact_structs( types )

            print( '... and finally:' )

            if self.config.diff:
                self._print_diff_of_structs( packed_types )
            else:
                self._dump_structs_to_files( packed_types )

            print( 'Done.' )

        except EBOError as e:
            print( 'File', file_name, 'skipped since', e )

    # details

    def _read_DWARF( self, file_name ):
        with open( file_name, 'rb' ) as file:
            elfFile = ELFFile( file )
            return self._read_DWARF_impl( elfFile )

    def _read_DWARF_impl( self, elfFile ):
        if not elfFile.has_dwarf_info():
            raise Exception( "File %s has no DWARF info" % file_name )

        dwarfInfo = elfFile.get_dwarf_info()
        return self.die_reader.process( dwarfInfo )

    def _get_types( self ):
        return self.die_reader.get_types()

    def _check_types_filter( self, struct ):
        if len( self.config.types ) == 0:
            return True

        for pattern in self.config.types:
            if pattern[ -1 ] == '*':
                if struct._get_name().startswith( pattern[ 0 : -1 ] ):
                    return True
            else:
                if struct._get_name() == pattern:
                    return True

        return False

    def _dump_structs_to_files( self, packed_structs ):
        for ( struct, packed ) in packed_structs:
            if packed == None:
                continue

            if self._check_types_filter( struct ) == False:
                continue

            struct_file_name = struct.get_name() + '.old.' + str( struct.get_size() ) + '.sc'
            packed_file_name = struct.get_name() + '.new.' + str( packed.get_size() ) + '.sc'

            struct_file = open( struct_file_name, 'w' )
            packed_file = open( packed_file_name, 'w' )

            sys.stdout = struct_file
            print_struct( struct, self.config.columns )

            sys.stdout = packed_file
            print_struct( packed, self.config.columns )

            struct_file.close()
            packed_file.close()

            sys.stdout = sys.__stdout__

            print( 'Files', struct_file_name, packed_file_name, 'created' )

    def _print_diff_of_structs( self, packed_structs ):
        for ( struct, packed ) in packed_structs:
            if packed == None:
                continue

            if self._check_types_filter( struct ) == False:
                continue

            if self.config.stdout:
                print_diff_of_structs( struct, packed, self.config.columns )
                print( '\n' )
            else:
                file_name = struct.get_name() + '.sc'
                file = open( file_name, 'w' )

                print( 'File', file_name, 'created.' )

                sys.stdout = file
                print_diff_of_structs( struct, packed, self.config.columns )
                file.close()
                sys.stdout = sys.__stdout__

    def _print_structs( self, types ):
        print_output_visitor = PrintStructVisitor()

        for id, type in types.items():
            if self._check_types_filter( type ) == False:
                continue

            type.accept( print_output_visitor, id )

    def _compact_structs( self, types ):
        visitor = CompactStructVisitor()

        packed_types = []

        for id, type in types.items():
            if self._check_types_filter( type ) == False:
                continue

            try:
                type.accept( visitor, None )

                packed = visitor.get_and_clear()

                if packed:
                    packed_types.append( ( type, packed ) )

            except EBOError as error:
                if self.config.warnings:
                    print( 'Warning: ', error )

        return packed_types

    def _detect_padding( self, types ):
        visitor = DetectPaddingVisitor()

        for id, type in types.items():
            try:
                type.accept( visitor, None )
            except EBOError as error:
                if self.config.warnings:
                    print( 'Warning: ', error )
            except TypeNotWellDefinedError as error:
                if self.config.warnings:
                    print( 'Warning: ', error )

        return types

    def _fix_types( self, types ):
        visitor = FixSizeAlignmentVisitor()

        for id, type in types.items():
            try:
                type.accept( visitor, None )
            except EBOError as error:
                if self.config.warnings:
                    print( 'Warning: ', error )

        return types

def process_argv( argv ):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description =
            "StructCompacter reads object (*.o) file in ELF format and using DWARF debug info"
            " detects structs and theirs members, calculates padding and tries such shuffle with"
            " members to minimalize padding space and save memory.",

        epilog =
            "examples:\n\n"
            "  Process file, save original type and packed one to files (*.old.sc/*.new.sc)\n"
            "  cc.py application.o\n\n"

            "  Process specified type, save original type and packed one to files (*.old.sc/*.new.sc)\n"
            "  cc.py -t SomeType -- application.o\n\n"

            "  Process file, save simple diff of type and packed one to one file (*.sc)\n"
            "  cc.py -d application.o\n\n"

            "  Process specified type, show result on screen\n"
            "  cc.py -s -t SomeType -- application.o\n\n"

            "  Process specified types, show it details, show result on screen\n"
            "  cc.py -s -v -t SomeTypes* -- application.o\n\n"

            "author:\n\n"
            "  Lukasz Czerwinski (wo3kie@gmail.com)(https://github.com/wo3kie/StructCompacter)"
    )

    parser.add_argument(
        '-t', '--types',
        default=[],
        nargs='+',
        help=
            'Process only particular types (eg.: MyType), '
            'common prefix may be specified with asterix (eg.: vector*).'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        default=False,
        help=
            'Print struct layout before compression.'
    )

    parser.add_argument(
        '-s', '--stdout',
        action='store_true',
        default=False,
        help=
            'Redirect output to stdout instead of create file(s).'
    )

    parser.add_argument(
        '-w', '--warnings',
        action='store_true',
        default=False,
        help=
            'Show warnings.'
    )

    parser.add_argument(
        '-c', '--columns',
        default=50,
        type=int,
        help=
            'Width of output in columns. To enforce outputs width types name'
            ' and members name are cut (eg. memb...). Minimal value'
            ' is 30. By default 50 is set.'
    )

    parser.add_argument(
        '-d', '--diff',
        action='store_true',
        default=False,
        help=
            'Create one file (*.sc) with simple diff instead of creating two files '
            '(*.old.sc/*.new.sc). Diff is implicitly set when --stdout option is used.'
    );

    parser.add_argument(
        'file',
        nargs=1,
        help=
            'Object file to be processed.'
    )

    result = parser.parse_args( argv )

    # check --columns
    #
    result.columns = max( 30, result.columns )

    # check diff & stdout
    #
    if result.stdout:
        result.diff = True

    return result

def main():
    config = process_argv( sys.argv[1:] )

    app = Application( config )
    app.process( config.file[0] )

if __name__ == "__main__":
    main()
