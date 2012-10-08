# Class Compacter

import argparse
import os
import sys

from math import ceil
from fractions import gcd

if sys.platform.startswith( 'win' ):
    sys.path.append( '..\\3rdParty\\pyelftools-0.20' )
elif sys.platform.startswith( 'linux' ):
    sys.path.append( '../3rdParty/pyelftools-0.20' )
else:
    exit( 'Apple?' )

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

def check_this_offset( this_offset, alignment ):
    if this_offset < 0:
        return False

    if this_offset % alignment != 0:
        return False

    return True

def soft_check_this_offset( this_offset, alignment ):
    if this_offset == None or alignment == None:
        return True

    return check_this_offset( this_offset, alignment )

def check_name( name ):
    return len( name ) > 0

def check_size( size ):
    if size <= 0:
        return False

    return True

def soft_check_size( size ):
    if size == None:
        return True

    return check_size( size )

def check_alignment( alignment, type_size ):
    if alignment > type_size:
        return False

    if alignment not in [ 1, 2, 4, 8 ]:
        return False

    return True

def soft_check_alignment( alignment, type_size ):
    if alignment == None or type_size == None:
        return True

    return check_alignment( alignment, type_size )

#
# Utils
#

def decode( values ):
    result = 0
    for value in reversed( values ):
        result = ( result << 7 ) + ( value & 0x7F )

    return result

def abbrev( text, length ):
    precondition( length >= 0 )

    if len( text ) <= length:
        result = text
    elif length <= 3:
        result = text
    else:
        result = text[0:length-3] + '...'

    postcondition( len( result ) <= length )

    return result

def is_template_name( text ):
    precondition( len( text ) > 0 )

    return text.find( '<' ) != -1

def is_stl_internal_name( text ):
    precondition( len( text ) > 0 )

    if text.startswith( '_' ):
        return True

    return False

def is_vtpr( text ):
    precondition( len( text ) > 0 )

    return text.startswith( '_vptr.' )

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
        precondition( check_name( name ) )
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
        precondition( soft_check_this_offset( this_offset, self.get_type().get_alignment() ) )

        self.this_offset = this_offset

    def get_size( self ):
        return self.type.get_size()

    def get_brief_desc( self ):
        pass

    def get_full_desc( self ):
        return self.get_brief_desc()

    # details

    def _set_type( self, type ):
        precondition( type )

        self.type = type

    def _get_name( self ):
        return self.name

    def __str__( self ):
        return self.get_full_desc()

class Inheritance( IMember ):
    def __init__( self, type, this_offset ):
        IMember.__init__( self, '__inheritance', type, this_offset )

    def is_moveable( self ):
        return False

    def get_brief_desc( self ):
        return self.get_name( 30 ) + ' ' \
            + self.type.get_name( 30 ) \
            + ' [this+' + str( self.this_offset ) + ']'

class Member( IMember ):
    def __init__( self, name, file_id, line_no, type, this_offset ):
        IMember.__init__( self, name, type, this_offset )

        self.file_id = file_id
        self.line_no = line_no

    def is_moveable( self ):
        if is_vptr( self.name ):
            return False

        return True

    def get_brief_desc( self ):
        return \
            self.get_name( 30 ) + ' ' \
            + self.type.get_desc( 30 ) \
            + ' [this+' + str( self.this_offset ) + ']'

    def get_full_desc( self ):
        return \
            self.get_name( 30 ) + ' ' \
            + ' (' + str( self.file_id ) + ':' + str( self.line_no ) + ') ' \
            + self.type.get_desc() \
            + ' [this+' + str( self.this_offset ) + ']'

class Padding( IMember ):
    def __init__( self, type, this_offset ):
        IMember.__init__( self, '        ', type, this_offset )

    def is_moveable( self ):
        return True

    def get_brief_desc( self ):
        return self.get_name( 30 ) + ' ' \
            + self.type.get_name( 30 ) \
            + ' [this+' + str( self.this_offset ) + ']'

#
# ConditionalStorage
#
class ConditionalStorage:
    def __init__( self, predicate, value = None ):
        self.predicate = predicate
        self.value = value

    def set( self, value ):
        if self.predicate( self.value, value ) == False:
            return False

        self.value = value
        return True

    def get( self ):
        return self.value

#
# predicates
#
def true_predicate( value1, value2 ):
    return True

def false_predicate( value1, value2 ):
    return False

def greater_than( value1, value2 ):
    if value1 == None and value2 == None:
        return False

    if value1 == None and value2 != None:
        return True

    if value1 != None and value2 == None:
        return False

    return value1 > value2

#
# Types representation
#
class IType( IVisitable ):
    def __init__( self, name, size ):
        precondition( check_name( name ) )
        precondition( soft_check_size( size ) )

        self.name = name

        if size == None:
            self.size = ConditionalStorage( greater_than, None )
        else:
            self.size = ConditionalStorage( false_predicate, size )

        self.alignment = ConditionalStorage( greater_than, None )

        self.is_declaration = False

    def set_name( self, name ):
        precondition( check_name( name ) )

        self.name = name

    def get_name( self, width = None ):
        if width == None:
            return self._get_name()

        result = self._decorate_name( \
                abbrev( self._get_name(), width - self._get_decoration_size() ) )

        postcondition( len( result ) <= width )

        return result

    def get_desc( self, width = None ):
        prefix = '['
        suffix = ' (' + str( self.get_size() ) + ':' + str( self.get_alignment() ) + ')]'

        if width == None:
            return prefix + self.get_name() + suffix

        result = prefix + self.get_name( width - len( prefix ) - len( suffix ) ) + suffix

        postcondition( len( result ) <= width )

        return result

    def try_set_size( self, size ):
        precondition( soft_check_size( size ) )

        return self.size.set( size )

    def get_size( self ):
        return self.size.get()

    def try_set_alignment( self, alignment ):
        precondition( soft_check_alignment( alignment, self.get_size() ) )

        return self.alignment.set( alignment )

    def get_alignment( self ):
        return self.alignment.get()

    def get_is_compactable( self ):
        return False

    def set_is_declaration( self, is_declaration ):
        self.is_declaration = is_declaration

    def get_is_declaration( self ):
        return self.is_declaration

    def get_is_completely_defined( self ):
        return False

    def get_is_well_defined( self ):
        return False

    # details

    def _get_name( self ):
        return self.name

    def _decorate_name( self, name ):
        return name

    def _get_decoration_size( self ):
        return 0

class UnknownType( IType ):
    def __init__( self ):
        IType.__init__( self, 'unknown', None )

    def get_alignment( self ):
        return 1

class PtrType( IType ):
    def __init__( self, type, size ):
        IType.__init__( self, 'Ptr', size )
        self.type = type

    def get_is_completely_defined( self ):
        return True

    def get_is_well_defined( self ):
        return True

    # details

    def _get_name( self ):
        return self.type.get_name()

    def _decorate_name( self, name ):
        return name + '*'

    def _get_decoration_size( self ):
        return 1

class RefType( IType ):
    def __init__( self, type, size ):
        IType.__init__( self, 'Ref', size )
        self.type = type

    def get_is_completely_defined( self ):
        return True

    def get_is_well_defined( self ):
        return True

    # details

    def _get_name( self ):
        return self.type.get_name()

    def _decorate_name( self, name ):
        return name + '&'

    def _get_decoration_size( self ):
        return 1

class ConstType( IType ):
    def __init__( self, type, size ):
        IType.__init__( self, 'Const', size )
        self.type = type

    def get_is_completely_defined( self ):
        return self.type.get_is_well_defined()

    def get_is_well_defined( self ):
        return self.type.get_is_well_defined()

    # details

    def _get_name( self ):
        return self.type.get_name()

    def _decorate_name( self, name ):
        return 'c{' + name + '}'

    def _get_decoration_size( self ):
        return 3

class VolatileType( IType ):
    def __init__( self, type, size ):
        IType.__init__( self, 'Volatile', size )
        self.type = type

    def get_is_completely_defined( self ):
        return self.type.get_is_well_defined()

    def get_is_well_defined( self ):
        return self.type.get_is_well_defined()

    # details

    def _get_name( self ):
        return self.type.get_name()

    def _decorate_name( self, name ):
        return 'v{' + name + '}'

    def _get_decoration_size( self ):
        return 3

class BaseType( IType ):
    def __init__( self, name, size ):
        IType.__init__( self, name, size )

    def get_is_completely_defined( self ):
        return True

    def get_is_well_defined( self ):
        return True

class UnionType( IType ):
    def __init__( self, name, size ):
        IType.__init__( self, name, size )

    def get_is_completely_defined( self ):
        return True

    def get_is_well_defined( self ):
        return True

    # details

    def _decorate_name( self, name ):
        return 'u{' + name + '}'

    def _get_decoration_size( self ):
        return 3

class ArrayType( IType ):
    def __init__( self, type ):
        IType.__init__( self, 'Array', None )

        self.type = type

    def get_is_completely_defined( self ):
        return self.get_type().get_is_well_defined()

    def get_is_well_defined( self ):
        return self.get_type().get_is_well_defined()

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
        IType.__init__( self, name, size )

        self.is_valid = True

        self.members = []

        self.compacted = None

    def set_packed( self, compacted ):
        self.compacted = compacted

    def get_packed( self ):
        return self.compacted

    def get_alignment( self ):
        return self.alignment.get()

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

        if self.get_is_well_defined():
            result += 'W'
        else:
            result += ' '

        if self.get_is_completely_defined():
            result += 'C'
        else:
            result += ' '

        result += ')'

        for member in self.members:
            result += '\n\t' + member.get_brief_desc()

        return result

    def add_member( self, member ):
        if member == None:
            return

        self.members.append( member )

    def get_members( self ):
        return self.members

    def set_members( self, members ):
        self.members = members

    def get_is_valid( self ):
        return self.is_valid

    def set_is_valid( self, is_valid ):
        self.is_valid = is_valid

    def get_is_compactable( self ):
        return True

    def get_is_completely_defined( self ):
        if self.get_is_declaration():
            return False

        for member in self.members:
            if member.get_type().get_is_completely_defined() == False:
                return False

        return True

    def get_is_well_defined( self ):
        if self.get_size() == 0:
            return False

        if self.get_alignment() == None:
            return False

        for member in self.members:
            if member.get_type().get_is_well_defined() == False:
                return False

        return True

    # details

    def _decorate_name( self, name ):
        return '{' + name + '}'

    def _get_decoration_size( self ):
        return 2

class EnumType( IType ):
    def __init__( self, name, size ):
        IType.__init__( self, name, size )

    def get_is_completely_defined( self ):
        return True

    def get_is_well_defined( self ):
        return True

    # details

    def _decorate_name( self, name ):
        return 'e{' + name + '}'

    def _get_decoration_size( self ):
        return 3

class PaddingType( IType ):
    def __init__( self, size ):
        IType.__init__( self, 'Padding', size )

    def get_alignment( self ):
        return 1

    def get_is_completely_defined( self ):
        return True

    def get_is_well_defined( self ):
        return True

    # details

    def _get_name( self ):
        return 'char[' + str( self.get_size() ) + ']'


class Alignment:
    @staticmethod
    def get_from_sizeof( size ):
        precondition( size > 0 )

        return gcd( 8, size )

    @staticmethod
    def get_from_position( this_offset, type_size ):
        precondition( this_offset >= 0 )
        precondition( type_size > 0 )

        for i in [ 8, 4, 2, 1 ]:
            if i > type_size:
                continue

            if this_offset % i == 0:
                return i

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

class EBOException( Exception ):
    def __init__( self, text ):
        Exception.__init__( self, text )

#
# fix_size_and_alignment
#
def fix_size_and_alignment( struct ):
    members = struct.get_members()

    if len( members ) == 0:
        struct.try_set_size( 128 * 128 )
        struct.try_set_alignment( min( struct.get_size(), 8 ) )

        return

    struct.try_set_alignment( Alignment.get_from_sizeof( struct.get_size() ) )

    # resolve all but last
    for i in range( 0, len( members ) -1 ):
        current = members[ i ]
        next = members[ i + 1 ]
        member_size = next.get_this_offset() - current.get_this_offset()

        if member_size <= 0:
            raise EBOException( 'EBO for type %s' % struct.get_name() )

        current.get_type().try_set_size( member_size )

        alignment \
            = Alignment.get_from_position( current.get_this_offset(), current.get_type().get_size() )

        current.get_type().try_set_alignment( alignment )

    # resolve last
    current = members[ -1 ]

    member_size = struct.get_size() - current.get_this_offset()

    if member_size <= 0:
        raise EBOException( 'EBO for type %s' % struct.get_name() )

    current.get_type().try_set_size( member_size )

    alignment \
        = Alignment.get_from_position( current.get_this_offset(), current.get_type().get_size() )

    current.get_type().try_set_alignment( alignment )

#
# find_and_create_padding_members
#
def find_and_create_padding_members( struct ):
    def _create_padding( previous_member, padding_size ):
        padding_this_offset = previous_member.get_this_offset() + previous_member.get_size()
        return Padding( PaddingType( padding_size ), padding_this_offset )

    members = struct.get_members()
    members_and_paddings = []

    if len( members ) == 0:
        return

    for i in range( 0, len( members ) - 1 ):
        current = members[ i ]
        next = members[ i + 1 ]
        padding_size = next.get_this_offset() - current.get_this_offset() - current.get_size()

        if padding_size < 0:
            raise EBOException( 'EBO for type %s' % struct.get_name() )

        members_and_paddings.append( current )

        if padding_size > 0:
            members_and_paddings.append( _create_padding( current, padding_size ) )

    current = members[ -1 ]
    padding_size = struct.get_size() - current.get_this_offset() - current.get_size()

    if padding_size < 0:
        raise EBOException( 'EBO for type %s' % struct.get_name() )

    members_and_paddings.append( current )

    if padding_size > 0:
        members_and_paddings.append( _create_padding( current, padding_size ) )

    struct.set_members( members_and_paddings )

#
# ITypeVisitor for IType hierarchy
#
class ITypeVisitor:
    def __init__( self ):
        self.dispatcher = {}

        self.dispatcher[ UnknownType ] = self.visit_unknown_type
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
        return

    def visit_ptr_type( self, ptr, * args ):
        return

    def visit_ref_type( self, ref, * args ):
        return

    def visit_const_type( self, const, * args ):
        return

    def visit_volatile_type( self, const, * args ):
        return

    def visit_base_type( self, base, * args ):
        return

    def visit_union_type( self, union, * args ):
        return

    def visit_declaration_type( self, declaration, * args ):
        return

    def visit_array_type( self, array, * args ):
        return

    def visit_struct_type( self, struct, * args ):
        return

    def visit_enum_type( self, enum, * args ):
        return

    def visit_padding_type( self, padding, * args ):
        return

#
# IMemberVisitor
#
class IMemberVisitor:
    def __init__( self ):
        self.dispatcher = {}

        self.dispatcher[ Member ] = self.visit_member
        self.dispatcher[ Inheritance ] = self.visit_inheritance
        self.dispatcher[ Padding ] = self.visit_padding

    def visit( self, interface, * args ):
        self.dispatcher[ interface.__class__ ]( interface, * args )

    def visit_member( self, member, * args ):
        return

    def visit_inheritance( self, inheritance, * args ):
        return

    def visit_padding( self, padding, * args ):
        return

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


def print_diff_of_structs( struct1, struct2, width ):
    def _format( member, width ):
        this_offset = ' (+' + str( member.get_this_offset() ) + ')'
        this_offset_len = len( this_offset )

        name_len = ( width // 2 ) - this_offset_len
        name = member.get_name( name_len )

        type_len = ( width // 2 )
        type = member.get_type().get_desc( type_len )

        return \
            ('{: <' + str( name_len ) + '}').format( name ) \
            + ('{: >' + str( this_offset_len ) + '}').format( this_offset ) \
            + ('{: <' + str( type_len ) + '}').format( type )

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
        print( _format( member1, width ), '|', _format( member2, width ) )

    if members_size == compacted_size:
        return

    empty_member_string = ( '{: <' + str( width ) + '}' ).format( '-' )

    # member type          | -
    if members_size > compacted_size:
        for i in range( compacted_size, members_size ):
            member1 = struct1.get_members()[ i ]
            print( _format( member1, width ), '|', empty_member_string )

    # -                    | member type
    if members_size < compacted_size:
        for i in range( members_size, compacted_size ):
            member2 = struct2.get_members()[ i ]
            print( empty_member_string, '|', _format( member2, width ) )

#
# PrintDiffOfStructAndPackedStruct
#
class PrintDiffOfStructAndPackedStruct( ITypeVisitor ):
    def __init__( self, config ):
        ITypeVisitor.__init__( self )

        self.config = config

    def visit_struct_type( self, struct, * args ):
        if not struct.get_packed():
            return

        if self.config.output == 'stdout':
            self._print_to_stdout( struct )
        else:
            self._print_to_file( struct )

    def _print_to_stdout( self, struct ):
        print_diff_of_structs( struct, struct.get_packed(), self.config.columns )
        print( '\n' )

    def _print_to_file( self, struct ):
        file_name = struct.get_name() + '.cc'
        file = open( file_name, 'w' )

        print( 'File', file_name, 'created.' )

        sys.stdout = file
        print_diff_of_structs( struct, struct.get_packed() )
        file.close()
        sys.stdout = sys.__stdout__

#
# INode
#
class INode( IMember ):
    def __init__( self, name, type, this_offset ):
        IMember.__init__( self, name, type, this_offset )

        self.next = None
        self.prev = None

    def get_size( self ):
        return self.get_type().get_size()

class HeadNode( INode ):
    def __init__( self ):
        INode.__init__( self, 'Head', UnknownType(), None )

    def get_this_offset( self ):
        return 0

    def get_size( self ):
        return 0

    def __str__( self ):
        return 'Head'

class EndNode( INode ):
    def __init__( self ):
        INode.__init__( self, 'End', UnknownType(), None )

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
        return 'Inheritance ' + self.type.get_desc()

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
        precondition( check_size( size ) )

        self._set_type( PaddingType( size ) )

    def __str__( self ):
        return '__padding [' + str( self.get_size() ) + ']'\
            ' +(' + str( self.get_this_offset() ) + ')'

#
# INodeVisitor
#
class INodeVisitor:
    def __init__( self ):
        self.dispatcher = {}

        self.dispatcher[ HeadNode ] = self.visit_head_node
        self.dispatcher[ MemberNode ] = self.visit_member_node
        self.dispatcher[ InheritanceNode ] = self.visit_inheritance_node
        self.dispatcher[ PaddingNode ] = self.visit_padding_node

    def visit( self, node, * args ):
        self.dispatcher[ node.__class__ ]( node, * args )

    def visit_head_node( self, head, * args ):
        return

    def visit_member_node( self, member, * args ):
        return

    def visit_inheritance_node( self, inheritance, * args ):
        return

    def visit_padding_node( self, padding, * args ):
        return

#
# TypesToNodesConversionVisitor
#
class TypesToNodesConversionVisitor( IMemberVisitor ):
    def __init__( self ):
        IMemberVisitor.__init__( self )

        self.node = None

    def visit_inheritance( self, inheritance, * args ):
        self.node = InheritanceNode( inheritance.get_type(), None )

    def visit_member( self, member, * args ):
        self.node = MemberNode( member.get_name(), member.get_type(), None )

    def visit_padding( self, padding, * args ):
        self.node = PaddingNode( padding.get_type(), None )

    def get_node( self ):
        return self.node

#
# FindMatchingPaddingVisitor
#
def check_padding( padding, size, alignment ):
    precondition( check_size( size ) )
    precondition( check_alignment( alignment, size ) )

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

    def get_type( self ):
        return self.type

#
# StructCompacter
#
class StructCompacter:
    def __init__( self ):
        self.type_to_node_conversion_visitor = TypesToNodesConversionVisitor()

        self.members_front = HeadNode()
        self.members_back = self.members_front

        self._init_dispatcher()

        self.struct = None

    def process( self, struct ):
        if struct.get_is_well_defined() == False:
            return None

        if calculate_total_padding( struct ) < struct.get_alignment():
            return None

        self.struct = struct

        try:
            self._pack_members()

            packed_struct_size \
                = self.__back().get_this_offset() + self.__back().get_size()

            if struct.get_size() == packed_struct_size:
                return None

            result = StructType( struct.get_name(), packed_struct_size )
            result.try_set_alignment( struct.get_alignment() )
            result.set_members( StructCompacter._convert_nodes_to_members( self.__front().next ) )

            return result

        except EBOException as exception:
            if self.config.warnings:
                print( 'Warning:', exception )

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
        self.dispatcher[ ( HeadNode, MemberNode ) ] = self._process_head_member
        self.dispatcher[ ( HeadNode, PaddingNode ) ] = self._process_head_padding

        self.dispatcher[ ( InheritanceNode, InheritanceNode ) ] = self._process_inheritance_inheritance
        self.dispatcher[ ( InheritanceNode, MemberNode ) ] = self._process_inheritance_member
        self.dispatcher[ ( InheritanceNode, PaddingNode ) ] = self._process_inheritance_padding

        self.dispatcher[ ( MemberNode, MemberNode ) ] = self._process_member_member
        self.dispatcher[ ( MemberNode, PaddingNode ) ] = self._process_member_padding

        self.dispatcher[ ( PaddingNode, MemberNode ) ] = self._process_padding_member
        self.dispatcher[ ( PaddingNode, PaddingNode ) ] = self._process_padding_padding

        self.dispatcher[ ( InheritanceNode, EndNode ) ] = self._process_inheritance_end
        self.dispatcher[ ( MemberNode, EndNode ) ] = self._process_member_end
        self.dispatcher[ ( PaddingNode, EndNode ) ] = self._process_padding_end

    def _process_inheritance_end( self, tail, end ):
        return

    def _process_member_end( self, tail, end ):
        struct_end = tail.get_this_offset() + tail.get_size()
        aligned_struct_end = Alignment.get_aligned_up( struct_end, self.struct.get_alignment() )

        back_padding_size = aligned_struct_end - struct_end

        if back_padding_size == 0:
            return

        back_padding = PaddingNode( PaddingType( back_padding_size ), struct_end )
        self.__append( back_padding )

    def _process_padding_end( self, tail, end ):
        back_padding_this_offset = tail.get_this_offset()
        aligned_struct_end \
            = Alignment.get_aligned_up( back_padding_this_offset, self.struct.get_alignment() )

        back_padding_new_size = aligned_struct_end - back_padding_this_offset
        back_padding_new_size = back_padding_new_size % self.struct.get_alignment()

        if back_padding_new_size == 0:
            self.__pop_back()
        elif tail.get_size() != back_padding_new_size:
            tail.set_size( back_padding_new_size )

    def _process_padding_padding( self, tail, padding ):
        total_padding_size = tail.get_size() + padding.get_size()
        total_padding_size = total_padding_size % self.struct.get_alignment()

        if total_padding_size == 0:
            self.__pop_back()
        elif tail.get_size() != total_padding_size:
            tail.set_size( total_padding_size )

    def _process_padding_member( self, tail, member ):
        member_size = member.get_size()
        member_alignment = member.get_type().get_alignment()

        found_padding \
            = StructCompacter._find_matching_padding( self.__front(), member_size, member_alignment )

        if found_padding != None:
            self._move_member_into_padding( found_padding, member )
        elif self._try_shrink_padding_right( tail, member ):
            return
        else:
            self._add_unaligned_member( member )

    def _process_member_padding( self, tail, padding ):
        padding.set_this_offset( self._get_aligned_struct_size( padding.get_type().get_alignment() ) )
        self.__append( padding )

    def _process_member_member( self, tail, member ):
        member_size = member.get_size()
        member_alignment = member.get_type().get_alignment()
        padding_node = self._find_matching_padding( self.__front(), member_size, member_alignment )

        if padding_node == None:
            self._add_unaligned_member( member )
        else:
            self._move_member_into_padding( padding_node, member )

    def _process_inheritance_padding( self, tail, padding ):
        padding.set_this_offset( self._get_aligned_struct_size( padding.get_type().get_alignment() ) )
        self.__append( padding )

    def _process_inheritance_inheritance( self, tail, inheritance ):
        self._add_unaligned_member( inheritance )

    def _process_inheritance_member( self, tail, member ):
        self._add_unaligned_member( member )

    def _process_head_inheritance( self, tail, inheritance ):
        inheritance.set_this_offset( 0 )
        self.__append( inheritance )

    def _process_head_member( self, tail, member ):
        member.set_this_offset( 0 )
        self.__append( member )

    def _process_head_padding( self, tail, padding ):
        padding.set_this_offset( 0 )
        self.__append( padding )

    #
    # details
    #

    def _pack_members( self ):
        for member in self.struct.get_members():
            tail = self.__back()
            node = self._convert_to_node( member )

            self.dispatch( tail, node )

            #StructCompacter._print( node, self.__front().next )

        self.dispatch( self.__back(), EndNode() )

    def _try_shrink_padding_right( self, padding, member ):
        if Alignment.is_aligned( padding.get_this_offset(), member.get_type().get_alignment() ):
            self.__pop_back()
        elif padding.get_size() < member.get_type().get_alignment():
            return False
        else:
            padding.set_size( padding.get_size() % member.get_type().get_alignment() )

        self._add_unaligned_member( member )

        return True

    def _get_aligned_struct_size( self, alignment ):
        struct_size = self.__back().get_this_offset() + self.__back().get_size()
        aligned_struct_size = Alignment.get_aligned_up( struct_size, alignment )

        return aligned_struct_size

    def _add_unaligned_member( self, member ):
        member.set_this_offset( self._get_aligned_struct_size( member.get_type().get_alignment() ) )

        alignment_padding = self._get_alignment_padding( member )

        if alignment_padding:
            self.dispatch( self.__back(), alignment_padding )

        self.__append( member )

    def _get_alignment_padding( self, member ):
        struct_end = self.__back().get_this_offset() + self.__back().get_size()
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

        self.__insert( padding, member )
        self.__erase( padding )

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

            self.__insert( padding, member )
            self.__insert( member, new_padding )

        elif front_padding_size != 0:
            padding.set_size( front_padding_size )

            self.__insert( padding, member )

        elif right_padding_size != 0:
            padding.set_size( right_padding_size )
            padding.set_this_offset( padding.get_this_offset() + member.get_size() )

            self.__insert( padding.prev, member )

    # list

    @staticmethod
    def _print( node, head ):
        print( '+{', str( node ), '}' )

        while head:
            print( str( head ) )
            head = head.next

        print( '\n' )

    def __front( self ):
        return self.members_front

    def __back( self ):
        return self.members_back

    def __append( self, node ):
        node.prev = self.members_back
        self.members_back.next = node

        self.members_back = node

    def __pop_back( self ):
        self.members_back = self.members_back.prev
        self.members_back.next.prev = None
        self.members_back.next = None

    def __erase( self, node ):
        if self.members_back == node:
            self.__pop_back()
            return None

        node.prev.next = node.next
        node.next.prev = node.prev

        result = node.next

        node.prev = None
        node.next = None

        return result

    def __insert( self, pos, node ):
        if self.members_back == pos:
            self.__append( node )
        else:
            node.next = pos.next
            node.next.prev = node

            node.prev = pos
            pos.next = node

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

    def visit_struct_type( self, struct, * args ):
        if self._skip_type( struct ):
            return

        struct_compacter = StructCompacter()
        compacted = struct_compacter.process( struct )
        struct.set_packed( compacted )

    # details

    def _skip_type( self, struct ):
        if is_template_name( struct.get_name() ):
            return True

        if is_stl_internal_name( struct.get_name() ):
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
        return is_template_name( DIE.get_name( die, dies ) )

    @staticmethod
    def is_stl( die, dies ):
        return is_stl_internal_name( DIE.get_name( die, dies ) )

    @staticmethod
    def is_local_class( die ):
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
    def __init__( self ):
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

    def _create_unknown_type( self, die ):
        unknown_type = UnknownType()
        self.types[ die.offset ] = unknown_type
        return unknown_type

    def _get_or_create_unknown_type( self, die ):
        if die.offset in self.types:
            return self.types[ die.offset ]
        else:
            return self._create_unknown_type( die )

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
            type = self._resolve_type_impl( die )
            self.types[ die.offset ] = type
            return type

    def _resolve_type_impl( self, die ):

        # process simple types

        name = DIE.get_name( die, self.dies )
        size = DIE.get_size( die )

        if die.tag == 'DW_TAG_base_type':
            return BaseType( name, size )
        elif die.tag == 'DW_TAG_union_type':
            return UnionType( name, size )
        elif die.tag == 'DW_TAG_class_type':
            return self._convert_die_to_struct( die )
        elif die.tag == 'DW_TAG_structure_type':
            return self._convert_die_to_struct( die )
        elif die.tag == 'DW_TAG_enumeration_type':
            return EnumType( name, size )

        # process derived types

        type_id = DIE.get_type_id( die, self.dies )

        if type_id == None:
            type = self._get_or_create_unknown_type( die )
        else:
            type = self._get_or_create_type( self.dies[ type_id ] )

        if die.tag == 'DW_TAG_member':
            return type
        elif die.tag == 'DW_TAG_inheritance':
            return type
        elif die.tag == 'DW_TAG_typedef':
            return type
        elif die.tag == 'DW_TAG_pointer_type':
            return PtrType( type, self.ptr_size )
        elif die.tag == 'DW_TAG_reference_type':
            return RefType( type, self.ref_size )
        elif die.tag == 'DW_TAG_array_type':
            return ArrayType( type )
        elif die.tag == 'DW_TAG_const_type':
            return ConstType( type, type.get_size() )
        elif die.tag == 'DW_TAG_volatile_type':
            return VolatileType( type, type.get_size() )
        else:
            return UnknownType()

    def _resolve_member_type( self, die ):
        type_id = DIE.get_type_id( die, self.dies )

        if type_id == None:
            return self._get_or_create_unknown_type( die )
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

    def _convert_die_to_struct( self, die ):
        assert DIE.is_struct( die ), 'die has to be a struct %s' % die.tag

        try:
            return self.types[ die.offset ]
        except KeyError:
            struct = StructType( '__not_know_yet__', None )
            self.types[ die.offset ] = struct

        struct.set_name( DIE.get_name( die, self.dies ) )
        struct.try_set_size( DIE.get_size( die ) )
        struct.set_is_declaration( DIE.is_declaration( die ) )

        for child in die.iter_children():
            if DIE.is_inheritance( child ):
                struct.add_member( self._convert_die_to_inheritance( child ) )
            elif DIE.is_member( child ):
                struct.add_member( self._convert_die_to_member( child ) )
            elif DIE.is_struct( child ):
                self._convert_die_to_struct( child )

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
        self.die_reader = DIEReader()

    def process( self, file_name ):
        try:
            print( 'Reading DWARF (may take some time)...' )
            types = self._read_DWARF( file_name )

            print( 'Fixing types...' )
            types = self._fix_types( types )

            print( 'Finding paddings...' )
            types = self._detect_padding( types )

            if self.config.debug:
                self._print_types( types )

            print( 'Compacting classes...' )
            types = self._compact_types( types )

            print( '... and finally:' )
            self._print_compacted( types )
            print( 'Done.' )

        except EBOException as e:
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

    def _print_compacted( self, types ):
        print_output_visitor = PrintDiffOfStructAndPackedStruct( self.config )

        for id, type in types.items():
            type.accept( print_output_visitor, None )

    def _print_types( self, types ):
        for id, type in types.items():
            if len( self.config.types ) != 0:
                if type._get_name() not in self.config.types:
                    continue

            if is_template_name( type._get_name() ):
                continue

            if is_stl_internal_name( type._get_name() ):
                continue

            if not type.get_is_compactable():
                continue

            if type.get_packed():
                print( '%x %s' % ( id, type.get_packed().get_full_desc() ) )
            else:
                print( '%x %s' % ( id, type.get_full_desc() ) )

    def _compact_types( self, types ):
        visitor = CompactStructVisitor()

        for id, type in types.items():
            if len( self.config.types ) > 0:
                if type.get_name() not in self.config.types:
                    continue

            try:
                type.accept( visitor, None )
            except EBOException as exception:
                if self.config.warnings:
                    print( 'Warning: ', exception )

                type.set_is_valid( False )

        return types

    def _detect_padding( self, types ):
        visitor = DetectPaddingVisitor()

        for id, type in types.items():
            try:
                type.accept( visitor, None )
            except EBOException as exception:
                if self.config.warnings:
                    print( 'Warning: ', exception )

                type.set_is_valid( False )

        return types

    def _fix_types( self, types ):
        visitor = FixSizeAlignmentVisitor()

        for id, type in types.items():
            try:
                type.accept( visitor, None )
            except EBOException as exception:
                if self.config.warnings:
                    print( 'Warning: ', exception )

                type.set_is_valid( False )

        return types

def process_argv( argv ):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description =
            "ClassCompacter reads object (*.o) file in ELF format and using DWARF debug info"
            " detects types and theirs members, calculates padding and tries such shuffle with"
            " members to minimalize padding space.",

        epilog =
            "Examples:\n"
            "cc.py application.o\n"
            "cc.py -d -t SomeType application.o\n"
            "cc.py -o stdout application.o\n"
            "Author: Lukasz Czerwinski (wo3kie@gmail.com)(https://github.com/wo3kie/ClassCompacter)"
    )

    parser.add_argument(
        '-t', '--types',
        default=[],
        nargs='+',
        help=
            'Process only particular types.'
    )

    parser.add_argument(
        '-d', '--debug',
        action='store_true',
        default=False,
        help=
            'Print debug information.'
    )

    parser.add_argument(
        '-o', '--output',
        default='files',
        help=
            'Output redirection (files/stdout).'
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
            'Width of output in columns (Not less than 40).'
    )

    parser.add_argument(
        'file',
        nargs=1,
        help=
            'Object file to be processed.'
    )

    result = parser.parse_args( argv )

    result.columns = max( 40, result.columns )

    return result

def main():
    config = process_argv( sys.argv[1:] )

    app = Application( config )
    app.process( config.file[0] )

if __name__ == "__main__":
    main()
