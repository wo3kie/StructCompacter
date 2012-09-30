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
def print_map_pretty( map ):
    for k, v in map.items():
        print( "%d : %s" % ( k, v ) )

def decode( values ):
    result = 0
    for value in reversed( values ):
        result = ( result << 7 ) + ( value & 0x7F )

    return result

def abbrev( text, length ):
    if len( text ) <= length:
        return text

    return text[0:length] + '...'

#
# Struct members representation
#
class Object:
    def __init__( self, type, this_offset ):
        self.type = type
        self.this_offset = this_offset

    def get_type( self ):
        return self.type

    def get_this_offset( self ):
        return self.this_offset

    def get_size( self ):
        return self.type.get_size()

    def get_brief_desc( self ):
        pass

    def get_full_desc( self ):
        return self.get_brief_desc()

    # details

    def __str__( self ):
        return self.get_full_desc()

class Inheritance( Object ):
    def __init__( self, type, this_offset ):
        Object.__init__( self, type, this_offset )

    def is_moveable( self ):
        return False

    def get_brief_desc( self ):
        return 'Inheritance ' \
            + self.type.get_brief_desc() \
            + ' [this+' + str( self.this_offset ) + ']'

class Member( Object ):
    def __init__( self, name, file_id, line_no, type, this_offset ):
        Object.__init__( self, type, this_offset )

        self.name = name
        self.file_id = file_id
        self.line_no = line_no

    def is_moveable( self ):
        if self.name.startswith( '_vptr.' ):
            return False

        return True

    def get_brief_desc( self ):
        return \
            abbrev( self.name, 30 ) \
            + ' ' \
            + self.type.get_brief_desc() \
            + ' [this+' + str( self.this_offset ) + ']'

    def get_full_desc( self ):
        return \
            abbrev( self.name, 30 ) \
            + ' (' + str( self.file_id ) + ':' + str( self.line_no ) + ') ' \
            + self.type.get_brief_desc() \
            + ' [this+' + str( self.this_offset ) + ']'

class Padding( Object ):
    def __init__( self, type, this_offset ):
        Object.__init__( self, type, this_offset )

    def is_moveable( self ):
        return True

    def get_brief_desc( self ):
        return \
            '\tpadding ' \
            + self.type.get_brief_desc() \
            + ' [this+' + str( self.this_offset ) + ']'


class Visitable:
    def accept( self, visitor, * args ):
        visitor.visit( self, * args )

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
class Type( Visitable ):
    def __init__( self, name, size ):
        self.name = name

        if size == None:
            self.size = UndefSize()
        else:
            self.size = DefinedSize( size )

    def set_name( self, name ):
        self.name = name

    def get_name( self ):
        return self._decorate_name( self._get_name() )

    def get_brief_name( self ):
        return self._decorate_name( abbrev( self._get_name(), 30 ) )

    def set_size( self, size ):
        self.size.set( size )

    def get_size( self ):
        return self.size.get()

    def get_alignment( self ):
        return self.get_size()

    def get_brief_desc( self ):
        return '[' + self.get_brief_name() \
            + ' (' + str( self.get_size() ) + ':' + str( self.get_alignment() ) + ')]'

    def get_full_desc( self ):
        return self.get_brief_desc()

    def get_is_compactable( self ):
        return False

    # details

    def _get_name( self ):
        return self.name

    def _decorate_name( self, name ):
        return name

class UnknownType( Type ):
    def __init__( self ):
        Type.__init__( self, 'unknown', None )

    def get_alignment( self ):
        return 8

class PtrType( Type ):
    def __init__( self, type, size ):
        Type.__init__( self, 'Ptr', size )
        self.type = type

    # details

    def _get_name( self ):
        return self.type.get_name()

    def _decorate_name( self, name ):
        return name + '*'

class RefType( Type ):
    def __init__( self, type, size ):
        Type.__init__( self, 'Ref', size )
        self.type = type

    # details

    def _get_name( self ):
        return self.type.get_name()

    def _decorate_name( self, name ):
        return name + '&'

class BaseType( Type ):
    def __init__( self, name, size ):
        Type.__init__( self, name, size )

class UnionType( Type ):
    def __init__( self, name, size ):
        Type.__init__( self, name, size )

    # details

    def _decorate_name( self, name ):
        return 'u{' + name + '}'

class ArrayType( Type ):
    def __init__( self, type ):
        Type.__init__( self, 'Array', None )

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
        return self.type.get_name()

    def _decorate_name( self, name ):
        return '[' + name + ']'

class StructType( Type ):
    def __init__( self, name, size ):
        Type.__init__( self, name, size )

        self.is_valid = True

        self.components = []

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
        return 's{' + name + '}'

class EnumType( Type ):
    def __init__( self, name, size ):
        Type.__init__( self, name, size )

    # details

    def _decorate_name( self, name ):
        return 'e{' + name + '}'

class PaddingType( Type ):
    def __init__( self, size ):
        Type.__init__( self, 'Padding', size )

    def get_brief_desc( self ):
        return '[' + self.get_name() + ' (' + str( self.get_size() ) + ':1)]'

    def get_alignment( self ):
        return 1

    # details

    def _decorate_name( self, name ):
        return 'p{' + name + '}'

#
# Visitor for Type hierarchy
#
class Visitor:
    def __init__( self ):
        self.dispatcher = {}

        self.dispatcher[ UnknownType ] = self.visit_unknown_type
        self.dispatcher[ PtrType ] = self.visit_ptr_type
        self.dispatcher[ RefType ] = self.visit_ref_type
        self.dispatcher[ BaseType ] = self.visit_base_type
        self.dispatcher[ UnionType ] = self.visit_union_type
        #self.dispatcher[ DeclarationType ] = self.visit_declaration_type
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

class CalculateTotalPaddingVisitor( Visitor ):
    def __init__( self ):
        Visitor.__init__( self )

        self.total_padding = 0

    def visit_padding_type( self, padding, * args ):
        self.total_padding += padding.get_size()

    def get_total_padding( self ):
        return self.total_padding

def calculate_total_padding( struct ):
    members = struct.get_members()

    total_padding_visitor = CalculateTotalPaddingVisitor()

    for member in members:
        member.get_type().accept( total_padding_visitor )

    return total_padding_visitor.get_total_padding()

class CompactStructVisitor( Visitor ):
    def __init__( self ):
        Visitor.__init__( self )

    def visit_struct_type( self, struct, * args ):
        try:
            self._resolve_type_size( struct )
            self._calculate_padding( struct )
        except Exception:
            struct.set_is_valid( False )

    # details

    def _calculate_padding( self, struct ):
        if struct.get_is_valid() == False:
            return

        members = struct.get_members()
        members_with_padding = []

        if len( members ) == 0:
            return

        for i in range( 0, len( members ) - 1 ):
            current = members[ i ]
            next = members[ i + 1 ]
            try:
                padding_size = next.get_this_offset() - current.get_this_offset() - current.get_size()
            except TypeError:
                breakHere = True

            if padding_size == 0:
                members_with_padding.append( current )
            elif padding_size > 0:
                members_with_padding.append( current )

                padding_this_offset = current.get_this_offset() + current.get_size()
                padding = Padding( PaddingType( padding_size ), padding_this_offset )
                members_with_padding.append( padding )
            else:
                raise Exception( 'EBO for type %s' % struct.get_name() )

        current = members[ -1 ]
        padding_size = struct.get_size() - current.get_this_offset() - current.get_size()

        if padding_size == 0:
            members_with_padding.append( current )
        elif padding_size > 0:
            members_with_padding.append( current )

            padding_this_offset = current.get_this_offset() + current.get_size()
            padding = Padding( PaddingType( padding_size ), padding_this_offset )
            members_with_padding.append( padding )
        else:
            raise Exception( 'EBO for type %s' % struct.get_name() )

        struct.set_members( members_with_padding )

    def _resolve_type_size( self, struct ):
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
        return DIE.get_name( die, dies ).count( '<' ) != 0

    @staticmethod
    def is_stl( die, dies ):
        return DIE.get_name( die, dies ).startswith( '_' )

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

def skip_type( die, dies ):
    if DIE.is_declaration( die ):
        return True

    if DIE.is_stl( die, dies ):
        return True

    if DIE.is_template( die, dies ):
        return True

    if DIE.is_local_class( die ):
        return True

    if DIE.get_name( die, dies ) == 'anonymous':
        return True

    return False

#
# DIEConverter from DWARF/DIEs into abstract representation of types
#
class DIEConverter:
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

    def get_types( self ):
        return self.types

    # details

    def _get_ptr_size( self, dwarf_info ):
        for cu in dwarf_info.iter_CUs():
            return cu[ 'address_size' ]

    def _decode_type_name( self, type_id ):
        return self._resolve_type( type_id ).get_brief_desc()

    def _decode_file_name( self, file_id ):
        return 'main.cpp'

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
# ClassCompacter
#
class ClassCompacter:
    def __init__( self ):
        self.dies = {}

        self.die_converter = DIEConverter()

    def process_file( self, fileName ):
        with open( fileName, 'rb' ) as file:
            try:
                elfFile = ELFFile( file )
            except ELFError:
                print( "Could not open ELF file: %s" % fileName )
                return

            self._process_DWARF( elfFile )

    # details

    def _process_DWARF( self, elfFile ):
        if not elfFile.has_dwarf_info():
            print( "File %s has no DWARF info" % fileName )
            return

        dwarfInfo = elfFile.get_dwarf_info()
        self.die_converter.process( dwarfInfo )

        self._compact_types()

        for id, type in self.die_converter.get_types().items():
            if type.get_name().count( '<' ) > 0:
                continue

            if type._get_name().startswith( '_' ):
                continue

            if not type.get_is_compactable():
                continue

            if calculate_total_padding( type ) == 0:
                continue

            print( '%x %s' % ( id, type.get_full_desc() ) )

    def _get_types( self ):
        return self.die_converter.get_types()

    def _compact_types( self ):
        compact_struct_visitor = CompactStructVisitor()

        for id, type in self._get_types().items():
            type.accept( compact_struct_visitor, None )

def main():
    for fileName in sys.argv[1:]:
        cc = ClassCompacter()
        cc.process_file( fileName )

if __name__ == "__main__":
    main()
