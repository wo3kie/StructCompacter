# Class Compacter

import sys

sys.path.append( '..\\3rdParty\\pyelftools-0.20' );
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from elftools.common.py3compat import bytes2str

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
            + abbrev( self.type.get_name(), 50 ) \
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
            + abbrev( self.type.get_name(), 50 ) \
            + ' [this+' + str( self.this_offset ) + ']'

    def is_moveable( self ):
        if self.name.startswith( '_vptr' ):
            return False

        return True

class Type:
    def get_name( self ):
        pass

    def get_size( self ):
        pass

    def get_desc( self ):
        pass

class UnknownType( Type ):
    def get_name( self ):
        return "unknown"

    def get_size( self ):
        return -1

    def get_desc( self ):
        return self.get_name()

    def calculate_padding( self ):
        pass

class PtrType( Type ):
    _size = None

    def set_size( size ):
        PtrType._size = size

    def __init__( self, type ):
        self.type = type

    def get_name( self ):
        return self.type.get_name() + '*'

    def get_size( self ):
        assert PtrType._size != None, 'Ptr size is not set'

        return PtrType._size

    def get_desc( self ):
        return self.get_name() + ' (' + str( self.get_size() ) + ')'

    def calculate_padding( self ):
        pass

class RefType( Type ):
    _size = None

    def set_size( size ):
        RefType._size = size

    def __init__( self, type ):
        self.type = type

    def get_name( self ):
        return self.type.get_name() + '&'

    def get_size( self ):
        assert RefType._size != None, 'Ref size is not set'

        return RefType._size

    def get_desc( self ):
        return self.get_name() + ' (' + str( self.get_size() ) + ')'

    def calculate_padding( self ):
        pass

class BaseType( Type ):
    def __init__( self, name, size ):
        self.name = name
        self.size = size

    def get_name( self ):
        return self.name

    def get_size( self ):
        return self.size

    def get_desc( self ):
        return self.get_name() + ' (' + str( self.get_size() ) + ')'

    def calculate_padding( self ):
        pass

class UnionType( Type ):
    def __init__( self, name, size ):
        self.name = name
        self.size = size

    def get_name( self ):
        return '{' + self.name + '}'

    def get_size( self ):
        return self.size

    def get_desc( self ):
        return self.get_name() + ' (' + str( self.get_size() ) + ')'

    def calculate_padding( self ):
        pass

class ArrayType( Type ):
    def __init__( self, type ):
        self.type = type

    def get_name( self ):
        return '[' + self.type.get_name() + ']'

    def get_size( self ):
        return -1

    def get_desc( self ):
        return self.get_name() + ' ()'

    def calculate_padding( self ):
        pass

class StructType( Type ):
    def __init__( self, name, size ):
        self.name = name
        self.size = size

        self.components = []

    def get_name( self ):
        return '{' + self.name + '}'

    def get_size( self ):
        return self.size

    def get_desc( self ):
        result = abbrev( self.get_name(), 50 ) + ' (' + str( self.get_size() ) + ')'

        for comp in self.components:
            result += '\n\t' + str( comp )

        return result

    def add_member( self, member ):
        if member == None:
            return

        self.components.append( member )

    def add_inheritance( self, inheritance ):
        if inheritance == None:
            return

        self.components.append( inheritance )

    def calculate_padding( self ):
        if len( self.components ) <= 1:
            return

        components = []
        components.append( self.components[0] )

        for i in range( 1, len( self.components ) ):
            previous = self.components[ i - 1 ]
            current = self.components[ i ]

            current_begin = current.get_this_offset()
            previous_end = previous.get_this_offset() + previous.get_size()
            
            if current_begin > previous_end:
                padding = Padding( current_begin - previous_end )
                member = Member( 'padding', -1, -1, padding, previous_end )
                components.append( member )

            components.append( current )

        self.components = components

class ConstType( Type ):
    pass

class VolatileType( Type ):
    pass

class EnumType( Type ):
    def __init__( self, name, size ):
        self.name = name
        self.size = size

    def get_name( self ):
        return self.name

    def get_size( self ):
        return self.size

    def get_desc( self ):
        return 'enum{' + self.get_name() + '} (' + str( self.get_size() ) + ')'

    def calculate_padding( self ):
        pass

class Padding( Type ):
    def __init__( self, size ):
        self.size = size

    def get_name( self ):
        return 'Padding' + ' (' + str( self.get_size() ) + ')'

    def get_size( self ):
        return self.size

    def get_desc( self ):
        return self.get_name()

    def calculate_padding( self ):
        pass
        
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

    def _is_struct( self, die ):
        return die.tag in ( 'DW_TAG_class_type', 'DW_TAG_structure_type' )

    def _is_static( self, die ):
        return 'DW_AT_external' in die.attributes

    def _is_member( self, die ):
        if die.tag != 'DW_TAG_member':
            return False
        elif self._is_static( die ):
            return False
        else:
            return True

    def _get_ptr_size( self, dwarf_info ):
        for cu in dwarf_info.iter_CUs():
            return cu[ 'address_size' ]

    def _get_name_impl( self, die ):
        return die.attributes[ 'DW_AT_name' ].value.decode( 'utf-8' )

    def _get_name( self, die ):
        try:
            return self._get_name_impl( die )
        except KeyError:
            pass

        try:
            specification_id = die.attributes[ 'DW_AT_specification' ].value
            specification_die = self.dies[ specification_id ]
            result = self._get_name( specification_die )

            return result

        except KeyError:
            return 'anonymous'

    def _get_size( self, die ):
        try:
            return die.attributes[ 'DW_AT_size' ].value
        except KeyError:
            pass

        try:
            return die.attributes[ 'DW_AT_byte_size' ].value
        except KeyError:
            pass

        raise KeyError( 'No DW_AT_(byte_)size for 0x%x' % die.offset )

    def _get_file_id( self, die ):
        try:
            return die.attributes[ 'DW_AT_decl_file' ].value
        except KeyError:
            return -1

    def _get_line_number( self, die ):
        if 'DW_AT_decl_line' in die.attributes:
            return die.attributes[ 'DW_AT_decl_line' ].value
        else:
            return -1

    def _get_type_id( self, die ):
        if 'DW_AT_type' in die.attributes:
            return die.attributes[ 'DW_AT_type' ].value

        if 'DW_AT_specification' in die.attributes:
            specification_id = die.attributes[ 'DW_AT_specification' ].value
            specification_die = self.dies[ specification_id ]
            result = self._get_type_id( specification_die )

            return result

        raise Exception( 'Can not get DW_AT_type for 0x%x' % die.offset )

    def _get_this_offset( self, die ):
        attr = die.attributes[ 'DW_AT_data_member_location' ]
        return decode( attr.value[1:] )

    def _decode_type_name( self, type_id ):
        return self._resolve_type( type_id ).get_desc()

    def _decode_file_name( self, file_id ):
        return 'main.cpp'

    def _resolve_type( self, type_id ):
        die = self.dies[ type_id ]

        if die.tag == 'DW_TAG_pointer_type':
            return PtrType( self._resolve_type( self._get_type_id( die ) ) )
        elif die.tag == 'DW_TAG_reference_type':
            return RefType( self._resolve_type( self._get_type_id( die ) ) )
        elif die.tag == 'DW_TAG_base_type':
            return BaseType( self._get_name( die ), self._get_size( die ) )
        elif die.tag == 'DW_TAG_typedef':
            return self._resolve_type( self._get_type_id( die ) )
        elif die.tag == 'DW_TAG_union_type':
            return UnionType( self._get_name( die ), self._get_size( die ) )
        elif die.tag == 'DW_TAG_array_type':
            return ArrayType( self._resolve_type( self._get_type_id( die ) ) )
        elif die.tag == 'DW_TAG_class_type':
            return StructType( self._get_name( die ), self._get_size( die ) )
        elif die.tag == 'DW_TAG_structure_type':
            return StructType( self._get_name( die ), self._get_size( die ) )
        elif die.tag == 'DW_TAG_const_type':
            return self._resolve_type( self._get_type_id( die ) )
        elif die.tag == 'DW_TAG_volatile_type':
            return self._resolve_type( self._get_type_id( die ) )
        elif die.tag == 'DW_TAG_enumeration_type':
            return EnumType( self._get_name( die ), self._get_size( die ) )
        else:
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
        assert self._is_member( die ), 'die has to be a member'

        name = self._get_name( die )
        file_id = self._get_file_id( die );
        line_no = self._get_line_number( die )
        type_id = self._get_type_id( die )
        type = self._get_or_create_type( type_id )
        this_offset = self._get_this_offset( die )

        return Member( name, file_id, line_no, type, this_offset )

    def _convert_die_to_inheritance( self, die ):
        assert self._is_inheritance( die ), 'die has to be a base object (inheritance)'

        type_id = self._get_type_id( die )
        type = self._get_or_create_type( type_id )
        this_offset = self._get_this_offset( die )

        return Inheritance( type, this_offset )

    def _is_template( self, die ):
        return self._get_name( die ).count( '<' ) != 0

    def _is_stl( self, die ):
        return self._get_name( die ).startswith( '_' )

    def _is_local_class( self, die ):
        # todo
        return False

    def _is_inheritance( self, die ):
        return die.tag == 'DW_TAG_inheritance'

    def _is_declaration( self, die ):
        return 'DW_AT_declaration' in die.attributes

    def _skip_type( self, die ):
        if self._is_declaration( die ):
            #print( '\tdeclaration skipped' )
            return True

        if self._is_stl( die ):
            #print( '\tSTL skipped' )
            return True

        if self._is_template( die ):
            #print( '\ttemplate skipped' )
            return True

        if self._is_local_class( die ):
            #print( '\tlocal class skipped' )
            return True

        if self._get_name( die ) == 'anonymous':
            #print( '\tno name skipped' )
            return True

        return False

    def _convert_die_to_struct( self, die ):
        if self._is_struct( die ) == False:
            return None

        try:
            if self._skip_type( die ):
                return None

            name = self._get_name( die )
            size = self._get_size( die )
            struct = StructType( name, size )

            for child in die.iter_children():
                if self._is_inheritance( child ):
                    struct.add_inheritance( self._convert_die_to_inheritance( child ) )
                elif self._is_member( child ):
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

    def processFile( self, fileName ):
        with open( fileName, 'rb' ) as file:
            try:
                elfFile = ELFFile( file )
            except ELFError:
                print( "Could not open ELF file: %s" % fileName )
                return

            self._processDWARF( elfFile )

    def getDIEs( self ):
        return self.dies

    def _processDWARF( self, elfFile ):
        if not elfFile.has_dwarf_info():
            print( "File %s has no DWARF info" % fileName )
            return

        dwarfInfo = elfFile.get_dwarf_info()
        self.die_converter.process( dwarfInfo )
        types = self.die_converter.get_types()

        for id, type in types.items():
            type.calculate_padding()

        for k,v in types.items():
            print( v.get_desc() )

def main():
    for fileName in sys.argv[1:]:
        cc = ClassCompacter()
        cc.processFile( fileName )

if __name__ == "__main__":
    main()
