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

class Inheritance( Object ):
    def __init__( self, type, this_offset ):
        Object.__init__( self, type, this_offset )

    def __str__( self ):
        return 'Inheritance ' \
            + self.type.get_brief_desc() \
            + ' [this+' + str( self.this_offset ) + ']'

    def is_moveable( self ):
        return False

class Member( Object ):
    def __init__( self, name, file_id, line_no, type, this_offset ):
        Object.__init__( self, type, this_offset )

        self.name = name
        self.file_id = file_id
        self.line_no = line_no

    def __str__( self ):
        return \
            abbrev( self.name, 30 ) \
            + ' (' + str( self.file_id ) + ':' + str( self.line_no ) + ') ' \
            + self.type.get_brief_desc() \
            + ' [this+' + str( self.this_offset ) + ']'

    def is_moveable( self ):
        if self.name.startswith( '_vptr' ):
            return False

        return True

#
# Types representation
#
class Type:
    def get_name( self ):
        return self._decorate_name( abbrev( self._get_name(), 30 ) )

    def get_size( self ):
        pass

    def get_brief_desc( self ):
        return '[' + self.get_name() + ' (' + str( self.get_size() ) + ')]'

    def get_full_desc( self ):
        return self.get_brief_desc()

    # details

    def _get_name( self ):
        pass

    def _decorate_name( self, name ):
        return name

class UnknownType( Type ):
    def get_size( self ):
        return None

    # details

    def _get_name( self ):
        return "unknown"

class PtrType( Type ):
    # static
    _size = None

    @staticmethod
    def set_size( size ):
        PtrType._size = size

    # interface

    def __init__( self, type ):
        self.type = type

    def get_size( self ):
        assert PtrType._size != None, 'PtrType::size is not set'

        return PtrType._size

    # details

    def _get_name( self ):
        return self.type.get_name()

    def _decorate_name( self, name ):
        return name + '*'

class RefType( Type ):
    # static
    _size = None

    @staticmethod
    def set_size( size ):
        RefType._size = size

    # interface

    def __init__( self, type ):
        self.type = type

    def get_size( self ):
        assert RefType._size != None, 'RefType::size is not set'

        return RefType._size

    # details

    def _get_name( self ):
        return self.type.get_name()

    def _decorate_name( self, name ):
        return name + '&'

class BaseType( Type ):
    def __init__( self, name, size ):
        self.name = name
        self.size = size

    # details

    def _get_name( self ):
        return self.name

    def get_size( self ):
        return self.size

class UnionType( Type ):
    def __init__( self, name, size ):
        self.name = name
        self.size = size

    # details

    def _get_name( self ):
        return self.name

    def _decorate_name( self, name ):
        return '{' + name + '}'

    def get_size( self ):
        return self.size

class ArrayType( Type ):
    def __init__( self, type ):
        self.type = type

    def get_brief_desc( self ):
        return '[' + self.get_name() + ' (?)]'

    def get_size( self ):
        # no such information in DWARF
        # type is known
        # number of items in array is not known
        raise None

    # details

    def _get_name( self ):
        return self.type.get_name()

    def _decorate_name( self, name ):
        return '[' + name + ']'

class DeclarationType( Type ):
    def __init__( self, name ):
        self.name = name
        self.size = None

    def get_brief_desc( self ):
        return '[' + self.get_name() + ' (?)]'

    def set_size( self, size ):
        self.size = size

    def get_size( self ):
        # in DWARF there is only declaration of the type
        # size is calculated later on and set explicitly
        assert self.size != None, 'DeclarationType::size is not set'

        return self.size

    # details

    def _get_name( self ):
        return self.name

    def _decorate_name( self, name ):
        return 'decl{' + name + '}'

class StructType( Type ):
    def __init__( self, name, size ):
        self.name = name
        self.size = size

        self.components = []

    def get_size( self ):
        return self.size

    def get_full_desc( self ):
        result = abbrev( self.get_name(), 50 ) + ' (' + str( self.get_size() ) + ')'

        for comp in self.components:
            result += '\n\t' + str( comp )

        return result

    def add_member( self, member ):
        if member == None:
            return

        self.components.append( member )

    # details

    def _get_name( self ):
        return self.name

    def _decorate_name( self, name ):
        return '{' + name + '}'

class EnumType( Type ):
    def __init__( self, name, size ):
        self.name = name
        self.size = size

    # details

    def _get_name( self ):
        return self.name

    def _decorate_name( self, name ):
        return 'enum{' + name + '}'

class PaddingType( Type ):
    def __init__( self, size ):
        self.size = size

    # details

    def _get_name( self ):
        return 'Padding'

    def _decorate_name( self, name ):
        return '{' + name + '}'

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

#
# DIEConverter from DWARF/DIEs into abstract representation of types
#
class DIEConverter:
    def __init__( self ):
        self.dies = {}
        self.types = {}

        self.ptr_size = -1

    def process( self, dwarf_info ):
        PtrType.set_size( self._get_ptr_size( dwarf_info ) )
        RefType.set_size( self._get_ptr_size( dwarf_info ) )

        self._make_dies_mapping( dwarf_info )

        self._process_dwarf_info( dwarf_info )

    def get_types( self ):
        return self.types

    # details

    def _process_dwarf_info( self, dwarf_info ):
        for cu in dwarf_info.iter_CUs():
            self._process_cu( cu )

    def _process_cu( self, cu ):
        top_die = cu.get_top_DIE()

        for die in top_die.iter_children():
            struct = self._convert_die_to_struct( die )

            if struct == None:
                continue

            self.types[ die.offset ] = struct

    def _get_ptr_size( self, dwarf_info ):
        for cu in dwarf_info.iter_CUs():
            return cu[ 'address_size' ]

    def _decode_type_name( self, type_id ):
        return self._resolve_type( type_id ).get_brief_desc()

    def _decode_file_name( self, file_id ):
        return 'main.cpp'

    def _resolve_type( self, type_id ):
        die = self.dies[ type_id ]

        # process types not dependent on 'DW_AT_size'
        if die.tag == 'DW_TAG_pointer_type':
            return PtrType( self._resolve_type( DIE.get_type_id( die, self.dies ) ) )
        elif die.tag == 'DW_TAG_reference_type':
            return RefType( self._resolve_type( DIE.get_type_id( die, self.dies ) ) )
        elif die.tag == 'DW_TAG_typedef':
            return self._resolve_type( DIE.get_type_id( die, self.dies ) )
        elif die.tag == 'DW_TAG_const_type':
            return self._resolve_type( DIE.get_type_id( die, self.dies ) )
        elif die.tag == 'DW_TAG_volatile_type':
            return self._resolve_type( DIE.get_type_id( die, self.dies ) )
        elif die.tag == 'DW_TAG_array_type':
            return ArrayType( self._resolve_type( DIE.get_type_id( die, self.dies ) ) )

        # process types with missing 'DW_AT_size'
        size = DIE.get_size( die )

        if size == None:
            return DeclarationType( DIE.get_name( die, self.dies ) )

        # process types with 'DW_AT_size'
        name = DIE.get_name( die, self.dies )

        if die.tag == 'DW_TAG_base_type':
            return BaseType( name, size )
        elif die.tag == 'DW_TAG_union_type':
            return UnionType( name, size )
        elif die.tag == 'DW_TAG_class_type':
            return StructType( name, size )
        elif die.tag == 'DW_TAG_structure_type':
            return StructType( name, size )
        elif die.tag == 'DW_TAG_enumeration_type':
            return EnumType( name, size )

        return UnknownType()

    def _get_or_create_type( self, type_id ):
        try:
            return self.types[ type_id ]
        except KeyError:
            pass

        type = self._resolve_type( type_id )

        self.types[ type_id ] = type

        return type

    def _convert_die_to_member( self, die ):
        assert DIE.is_member( die ), 'die has to be a member'

        name = DIE.get_name( die, self.dies )
        file_id = DIE.get_file_id( die );
        line_no = DIE.get_line_number( die )
        type_id = DIE.get_type_id( die, self.dies )
        type = self._get_or_create_type( type_id )
        this_offset = DIE.get_this_offset( die )

        return Member( name, file_id, line_no, type, this_offset )

    def _convert_die_to_inheritance( self, die ):
        assert DIE.is_inheritance( die ), 'die has to be a base object (inheritance)'

        type_id = DIE.get_type_id( die, self.dies )
        type = self._get_or_create_type( type_id )
        this_offset = DIE.get_this_offset( die )

        return Inheritance( type, this_offset )


    def _skip_type( self, die ):
        if DIE.is_declaration( die ):
            return True

        if DIE.is_stl( die, self.dies ):
            return True

        if DIE.is_template( die, self.dies ):
            return True

        if DIE.is_local_class( die ):
            return True

        if DIE.get_name( die, self.dies ) == 'anonymous':
            return True

        return False

    def _convert_die_to_struct( self, die ):
        if DIE.is_struct( die ) == False:
            return None

        try:
            if self._skip_type( die ):
                return None

            name = DIE.get_name( die, self.dies )
            size = DIE.get_size( die )
            struct = StructType( name, size )

            for child in die.iter_children():
                if DIE.is_inheritance( child ):
                    struct.add_member( self._convert_die_to_inheritance( child ) )
                elif DIE.is_member( child ):
                    struct.add_member( self._convert_die_to_member( child ) )

        except KeyError as error:
            print( '\tError:', error, '- skipped' )
            return None

        except Exception as error:
            print( '\tError:', error, '- skipped' )
            return None

        return struct

    def _make_dies_mapping_recursively( self, die ):
        self.dies[ die.offset ] = die

        for children in die.iter_children():
            self._make_dies_mapping_recursively( children )

    def _make_dies_mapping( self, dwarf_info ):
        for cu in dwarf_info.iter_CUs():
            top_die = cu.get_top_DIE()

            self._make_dies_mapping_recursively( top_die )

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

        for id, type in self.die_converter.get_types().items():
            print( type.get_full_desc() )

    def _compact_types( self ):
        pass

def main():
    for fileName in sys.argv[1:]:
        cc = ClassCompacter()
        cc.process_file( fileName )

if __name__ == "__main__":
    main()
