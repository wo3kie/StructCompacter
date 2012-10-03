# Class Compacter

import sys

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
# Utils
#

def decode( values ):
    result = 0
    for value in reversed( values ):
        result = ( result << 7 ) + ( value & 0x7F )

    return result

def abbrev( text, length ):
    if len( text ) <= length:
        return text

    if length <= 3:
        return text

    return text[0:length-3] + '...'

def is_template_name( text ):
    return text.find( '<' ) != -1

def is_stl_internal_name( text ):
    return text.startswith( '_' )

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
        self.this_offset = this_offset

    def get_size( self ):
        return self.type.get_size()

    def get_brief_desc( self ):
        pass

    def get_full_desc( self ):
        return self.get_brief_desc()

    # details

    def _set_type( self, type ):
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
        if self.name.startswith( '_vptr.' ):
            return False

        return True

    def get_brief_desc( self ):
        return \
            self.get_name( 30 ) + ' ' \
            + self.type.get_name( 30 ) \
            + ' [this+' + str( self.this_offset ) + ']'

    def get_full_desc( self ):
        return \
            self.get_name( 30 ) + ' ' \
            + ' (' + str( self.file_id ) + ':' + str( self.line_no ) + ') ' \
            + self.type.get_name( 30 ) \
            + ' [this+' + str( self.this_offset ) + ']'

class Padding( IMember ):
    def __init__( self, type, this_offset ):
        IMember.__init__( self, '__padding', type, this_offset )

    def is_moveable( self ):
        return True

    def get_brief_desc( self ):
        return self.get_name( 30 ) + ' ' \
            + self.type.get_name( 30 ) \
            + ' [this+' + str( self.this_offset ) + ']'

#
# Size
#
class Size:
    def set( self, value ):
        pass

    def get( self ):
        pass

class DefinedSize( Size ):
    def __init__( self, size ):
        self.size = size

    def set( self, size ):
        pass

    def get( self ):
        return self.size

class UndefSize( Size ):
    def __init__( self ):
        self.size = None

    def set( self, size ):
        if self.size == None:
            self.size = size
        elif self.size > size:
            self.size = size
        else:
            pass

    def get( self ):
        return self.size

#
# Types representation
#
class IType( IVisitable ):
    def __init__( self, name, size ):
        self.name = name

        if size == None:
            self.size = UndefSize()
        else:
            self.size = DefinedSize( size )

    def set_name( self, name ):
        self.name = name

    def get_name( self, width = None ):
        if width == None:
            return self._get_name()
        else:
            return self._decorate_name( \
                abbrev( self._get_name(), width - self._get_decoration_size() ) )

    def get_desc( self, width = None ):
        prefix = '['
        suffix = ' (' + str( self.get_size() ) + ':' + str( self.get_alignment() ) + ')]'

        if width == None:
            return prefix + self.get_name() + suffix
        else:
            return prefix + self.get_name( width - len( prefix ) - len( suffix ) ) + suffix

    def set_size( self, size ):
        self.size.set( size )

    def get_size( self ):
        return self.size.get()

    def get_alignment( self ):
        return self.get_size()

    def get_is_compactable( self ):
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
        return 8

class PtrType( IType ):
    def __init__( self, type, size ):
        IType.__init__( self, 'Ptr', size )
        self.type = type

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

    # details

    def _get_name( self ):
        return self.type.get_name()

    def _decorate_name( self, name ):
        return name + '&'

    def _get_decoration_size( self ):
        return 1

class BaseType( IType ):
    def __init__( self, name, size ):
        IType.__init__( self, name, size )

class UnionType( IType ):
    def __init__( self, name, size ):
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

    def get_name( self, width = None ):
        return self.type.get_name()

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

    def _decorate_name( self, name ):
        return self.get_name() + '[?]'

    def _get_decoration_size( self ):
        return 3

class StructType( IType ):
    def __init__( self, name, size ):
        IType.__init__( self, name, size )

        self.is_valid = True

        self.components = []

        self.compacted = None

    def set_compacted( self, compacted ):
        self.compacted = compacted

    def get_packed( self ):
        return self.compacted

    def get_alignment( self ):
        alignment = 1

        for member in self.get_members():
            member_alignment = member.get_type().get_alignment()

            if member_alignment > alignment:
                alignment = member_alignment

        return alignment

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

        if self.get_is_valid() == False:
            result += ' (!)'

        for comp in self.components:
            result += '\n\t' + comp.get_brief_desc()

        return result

    def add_member( self, member ):
        if member == None:
            return

        self.components.append( member )

    def get_members( self ):
        return self.components

    def set_members( self, members ):
        self.components = members

    def get_is_valid( self ):
        return self.is_valid

    def set_is_valid( self, is_valid ):
        self.is_valid = is_valid

    def get_is_compactable( self ):
        return True

    # details

    def _decorate_name( self, name ):
        return '{' + name + '}'

    def _get_decoration_size( self ):
        return 2

class EnumType( IType ):
    def __init__( self, name, size ):
        IType.__init__( self, name, size )

    # details

    def _decorate_name( self, name ):
        return 'e{' + name + '}'

    def _get_decoration_size( self ):
        return 3

class PaddingType( IType ):
    def __init__( self, size ):
        IType.__init__( self, None, size )

    def get_alignment( self ):
        return 1

    def _get_name( self ):
        return 'char[' + str( self.get_size() ) + ']'

#
# resolve_members_type_size
#
def resolve_members_type_size( struct ):
    if struct.get_is_valid() == False:
        return

    members = struct.get_members()

    if len( members ) == 0:
        return

    # resolve all but last
    for i in range( 0, len( members ) -1 ):
        current = members[ i ]
        next = members[ i + 1 ]
        type_size = next.get_this_offset() - current.get_this_offset()

        current.get_type().set_size( type_size )

    # resolve last
    current = members[ -1 ]
    type_size = struct.get_size() - current.get_this_offset()

    current.get_type().set_size( type_size )

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
    members_with_padding = []

    if len( members ) == 0:
        return

    for i in range( 0, len( members ) - 1 ):
        current = members[ i ]
        next = members[ i + 1 ]
        padding_size = next.get_this_offset() - current.get_this_offset() - current.get_size()

        if padding_size == 0:
            members_with_padding.append( current )
        elif padding_size > 0:
            members_with_padding.append( current )
            members_with_padding.append( _create_padding( current, padding_size ) )
        else:
            raise Exception( 'EBO for type %s' % struct.get_name() )

    current = members[ -1 ]
    padding_size = struct.get_size() - current.get_this_offset() - current.get_size()

    if padding_size == 0:
        members_with_padding.append( current )
    elif padding_size > 0:
        members_with_padding.append( current )
        members_with_padding.append( _create_padding( current, padding_size ) )
    else:
        raise Exception( 'EBO for type %s' % struct.get_name() )

    struct.set_members( members_with_padding )

#
# ITypeVisitor for IType hierarchy
#
class ITypeVisitor:
    def __init__( self ):
        self.dispatcher = {}

        self.dispatcher[ UnknownType ] = self.visit_unknown_type
        self.dispatcher[ PtrType ] = self.visit_ptr_type
        self.dispatcher[ RefType ] = self.visit_ref_type
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

    def visit_ref_type( self, refe, * args ):
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
        self.total_padding += padding.get_size()

    def get_total_padding( self ):
        return self.total_padding

def calculate_total_padding( struct ):
    members = struct.get_members()

    total_padding_visitor = CalculateTotalPaddingVisitor()

    for member in members:
        member.accept( total_padding_visitor )

    return total_padding_visitor.get_total_padding()

#
# IsDerivedClassVisitor
#
class IsDerivedClassVisitor( IMemberVisitor ):
    def __init__( self ):
        IMemberVisitor.__init__( self )

        self.is_derived_class = False

    def visit_inheritance( self, padding, * args ):
        self.is_derived_class = True

    def get_is_base_class( self ):
        return self.is_derived_class

def is_derived_class( struct ):
    members = struct.get_members()

    is_base_class_visitor = IsDerivedClassVisitor()

    for member in members:
        member.accept( is_base_class_visitor )

        if is_base_class_visitor.get_is_base_class():
            return True

    return False

def print_diff_of_structs( struct1, struct2 ):
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

    width = 60

    print( '{' + struct1.get_name() + '}' )

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
    def __init__( self ):
        ITypeVisitor.__init__( self )

    def visit_struct_type( self, struct, * args ):
        if not struct.get_packed():
            return

        print_diff_of_structs( struct, struct.get_packed() )

        print( '\n' )

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
        INode.__init__( self, 'Head', None, None )

    def get_size( self ):
        return 0

    def get_this_offset( self ):
        return 0

    def __str__( self ):
        return 'Head'

class InheritanceNode( INode ):
    def __init__( self, type, this_offset ):
        INode.__init__( self, '__inheritance', type, this_offset )

    def __str__( self ):
        return 'Inheritance'

class MemberNode( INode ):
    def __init__( self, name, type, this_offset ):
        INode.__init__( self, name, type, this_offset )

    def __str__( self ):
        return self.get_name() + ' ' + self.get_type().get_name() \
            + ' (' + str( self.get_type().get_size() ) + ')' \
            + ' +(' + str( self.get_this_offset() ) + ')'

class PaddingNode( INode ):
    def __init__( self, type, this_offset ):
        INode.__init__( self, '__padding', type, this_offset )

    def set_size( self, size ):
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
# FindPaddingVisitor
#
def check_padding( padding, size, alignment ):
    if padding.get_size() < size:
        return False

    return True

class FindPaddingVisitor( INodeVisitor ):
    def __init__( self, size, alignment ):
        INodeVisitor.__init__( self )

        self.size = size
        self.alignment = alignment

        self.padding = None

    def visit_padding_node( self, padding, * args ):
        if check_padding( padding, self.size, self.alignment ):
            self.padding = padding

    def get_padding( self ):
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
        pass

    def get_type( self ):
        return self.type

#
# StructCompacter
#
class StructCompacter:
    def __init__( self ):
        self.type_to_node_conversion_visitor = TypesToNodesConversionVisitor()

        self.members_head = HeadNode()
        self.members_tail = self.members_head

        self._init_dispatcher()

        self.struct = None

    def process( self, struct ):
        if calculate_total_padding( struct ) < struct.get_alignment():
            return None

        if is_derived_class( struct ):
            return None

        return self._process_impl( struct )

    def dispatch( self, object1, object2 ):
        self.dispatcher[ ( object1.__class__, object2.__class__ ) ]( object1, object2 )

    def _process_impl( self, struct ):
        self.struct = struct

        for member in struct.get_members():
            tail = self.members_tail
            node = self._convert_to_node( member )

            self.dispatch( tail, node )

        result = StructType( struct.get_name(), None )

        members = StructCompacter._convert_nodes_to_members( self.members_head.next )
        result.set_members( members )

        return result

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

    @staticmethod
    def print( self, node ):
        node = self.members_head

        while node:
            print( str( node ) )
            node = node.next

        print( '\n' )

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

    def _process_padding_padding( self, tail, padding ):
        new_size = self.members_tail.get_size() + padding.get_size()
        self.members_tail.set_size( new_size )

    def _append_node_to_members_list( self, node ):
        node.prev = self.members_tail
        self.members_tail.next = node

        self.members_tail = node

        node.set_this_offset( node.prev.get_this_offset() + node.prev.get_size() )

    def _process_padding_member( self, tail, member ):
        member_size = member.get_type().get_size()
        member_alignment = member.get_type().get_alignment()
        padding_node = StructCompacter._find_padding( self.members_head, member_size, member_alignment )

        if padding_node == None:
            self._append_node_to_members_list( member )
        else:
            self._put_member_into_padding( padding_node, member )
            self.dispatch( self.members_tail, PaddingNode( PaddingType( member_size ), None ) )

    def _process_member_padding( self, tail, padding ):
        self._append_node_to_members_list( padding )

    def _process_member_member( self, tail, member ):
        member2_size = member.get_type().get_size()
        member2_alignment = member.get_type().get_alignment()
        padding_node = self._find_padding( self.members_head, member2_size, member2_alignment )

        if padding_node == None:
            self._append_node_to_members_list( member )
        else:
            self._put_member_into_padding( padding_node, member )
            self.dispatch( self.members_tail, PaddingNode( PaddingType( member2_size ), None ) )

    def _process_inheritance_padding( self, tail, padding ):
        print( '_process_inheritance_padding' )

    def _process_inheritance_inheritance( self, tail, inheritance2 ):
        print( '_process_inheritance_inheritance' )

    def _process_inheritance_member( self, tail, member ):
        print( '_process_inheritance_member' )

    def _process_head_inheritance( self, tail, inheritance ):
        print( '_process_head_inheritance' )

    def _process_head_member( self, tail, member ):
        self._append_node_to_members_list( member )

    def _process_head_padding( self, tail, padding ):
        self._append_node_to_members_list( padding )

    def _convert_to_node( self, member ):
        member.accept( self.type_to_node_conversion_visitor )
        return self.type_to_node_conversion_visitor.get_node()

    def _put_member_into_padding( self, padding, member ):
        if padding.get_size() == member.get_type().get_size():
            member.next = padding.next

            if member.next:
                member.next.prev = member

            member.prev = padding.prev
            padding.prev.next = member

            if padding == self.members_tail:
                self.members_tail = member

            member.set_this_offset( padding.get_this_offset() )
        else:
            padding.set_size( padding.get_size() - member.get_type().get_size() )

            member.prev = padding.prev
            member.prev.next = member

            member.next = padding
            member.next.prev = member

            member.set_this_offset( padding.get_this_offset() )
            padding.set_this_offset( member.get_this_offset() + member.get_size() )

    @staticmethod
    def _find_padding( head, size, alignment ):
        find_padding_visitor = FindPaddingVisitor( size, alignment )

        while head:
            head.accept( find_padding_visitor )

            if find_padding_visitor.get_padding():
                return find_padding_visitor.get_padding()

            head = head.next

        return None

#
# CompactStructVisitor
#
class CompactStructVisitor( ITypeVisitor ):
    def __init__( self ):
        ITypeVisitor.__init__( self )

    def visit_struct_type( self, struct, * args ):
        try:
            resolve_members_type_size( struct )
            find_and_create_padding_members( struct )
        except Exception:
            struct.set_is_valid( False )

        if self._skip_type( struct ):
            return

        struct_compacter = StructCompacter()

        compacted = struct_compacter.process( struct )

        struct.set_compacted( compacted )

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
        elif die.tag == 'DW_TAG_const_type':
            return type
        elif die.tag == 'DW_TAG_volatile_type':
            return type
        elif die.tag == 'DW_TAG_pointer_type':
            return PtrType( type, self.ptr_size )
        elif die.tag == 'DW_TAG_reference_type':
            return RefType( type, self.ref_size )
        elif die.tag == 'DW_TAG_array_type':
            return ArrayType( type )
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
            struct = StructType( None, None )
            self.types[ die.offset ] = struct

        struct.set_name( DIE.get_name( die, self.dies ) )
        struct.set_size( DIE.get_size( die ) )

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
    def __init__( self ):
        self.dies = {}

        self.die_reader = DIEReader()

    def process( self, file_name ):
        types = self._read_DWARF( file_name )
        types = self._compact_types( types )
        self.__print_result( types )

    # details

    def _read_DWARF( self, file_name ):
        with open( file_name, 'rb' ) as file:
            try:
                elfFile = ELFFile( file )
            except ELFError:
                print( "Could not open ELF file: %s" % file_name )
            else:
                return self._read_DWARF_impl( elfFile )

    def _read_DWARF_impl( self, elfFile ):
        if not elfFile.has_dwarf_info():
            print( "File %s has no DWARF info" % file_name )
            return

        dwarfInfo = elfFile.get_dwarf_info()
        return self.die_reader.process( dwarfInfo )

    def _get_types( self ):
        return self.die_reader.get_types()

    def __print_result( self, types ):
        print_output_visitor = PrintDiffOfStructAndPackedStruct()

        for id, type in types.items():
            type.accept( print_output_visitor, None )

    def _print_result( self, types ):
        for id, type in types.items():
            if type.get_name().count( '<' ) > 0:
                continue

            if type._get_name().startswith( '_' ):
                continue

            if not type.get_is_compactable():
                continue

            if calculate_total_padding( type ) == 0:
                continue

            print( '%x %s' % ( id, type.get_full_desc() ) )

    def _compact_types( self, types ):
        compact_struct_visitor = CompactStructVisitor()

        for id, type in types.items():
            type.accept( compact_struct_visitor, None )

        return types

def main():
    for file_name in sys.argv[1:]:
        app = Application()
        app.process( file_name )

if __name__ == "__main__":
    main()
