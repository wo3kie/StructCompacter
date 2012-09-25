# Class Compacter

import sys

sys.path.append( '..\\3rdParty\\pyelftools-0.20' );
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from elftools.common.py3compat import bytes2str

def printPrettyMap( map ):
    for k, v in map.items():
        print( "%d : %s" % ( k, v ) )

def decode( values ):
    result = 0
    for value in reversed( values ):
        result = ( result << 7 ) + ( value & 0x7F )

    return result

class Object:
    pass

class Inheritance:
    pass

class Member( Object ):
    pass

class Struct:
    def add_member( self, member ):
        if member == None:
            return

class Type:
    def __init__( self, name, size ):
        self.name = name
        self.size = size

    def get_name( self ):
        return self.name

    def get_size( self ):
        return self.size

class UnknownType( Type ):
    def __init__( self ):
        Type.__init__( self, "unknown", -1 )

class PtrType( Type ):
    def __init__( self, name, size ):
        Type.__init__( self, name, size )

    def get_name( self ):
        return Type.get_name( self ) + '*';

class RefType( PtrType ):
    def __init__( self, name, size ):
        PtrType.__init__( self, name, size )

    def get_name( self ):
        return self.name + '&';

class BaseType( Type ):
    def __init__( self, name, size ):
        Type.__init__( self, name, size )

class UnionType( Type ):
    def __init__( self, name, size ):
        Type.__init__( self, name, size )

    def get_name( self ):
        return '{' + Type.get_name( self ) + '}';

class ArrayType( Type ):
    def __init__( self, name ):
        Type.__init__( self, name, -1 )

    def get_name( self ):
        return '[' + Type.get_name( self ) + ']';

class StructType( Type ):
    def __init__( self, name, size = 8 ):
        Type.__init__( self, name, size )

    def get_name( self ):
        return '{' + Type.get_name( self ) + '}';

class DIEConverter:
    def __init__( self ):
        self.dies = {}
        self.ptr_size = 4

    def process( self, dwarf_info ):
        self._ptr_size = self._get_ptr_size( dwarf_info )

        self._make_dies_mapping( dwarf_info )

        self._process_dwarf_info( dwarf_info )

    def _process_dwarf_info( self, dwarf_info ):
        for cu in dwarf_info.iter_CUs():
            self._process_cu( cu )

    def _process_cu( self, cu ):
        top_die = cu.get_top_DIE()

        for die in top_die.iter_children():
            self._convert_die_to_struct( die )

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
            return -1

    def _get_file_id( self, die ):
        try:
            return die.attributes[ 'DW_AT_decl_file' ].value
        except KeyError:
            return None

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

        raise Exception( 'Can not get DW_AT_type' )

    def _get_this_offset( self, die ):
        attr = die.attributes[ 'DW_AT_data_member_location' ]
        return decode( attr.value[1:] )

    def _decode_type_name( self, type_id ):
        return self._resolve_type( type_id ).get_name()

    def _decode_file_name( self, file_id ):
        return 'main.cpp'

    def _resolve_type( self, type_id ):
        try:
            die = self.dies[ type_id ]

            if die.tag == 'DW_TAG_pointer_type':
                return PtrType( self._resolve_type( self._get_type_id( die ) ).get_name(), self._ptr_size )
            elif die.tag == 'DW_TAG_reference_type':
                return RefType( self._resolve_type( self._get_type_id( die ) ).get_name(), self._ptr_size )
            elif die.tag == 'DW_TAG_base_type':
                return BaseType( self._get_name( die ), self._get_size( die ) )
            elif die.tag == 'DW_TAG_typedef':
                return self._resolve_type( self._get_type_id( die ) )
            elif die.tag == 'DW_TAG_union_type':
                return UnionType( self._get_name( die ), self._get_size( die ) )
            elif die.tag == 'DW_TAG_array_type':
                return ArrayType( self._resolve_type( self._get_type_id( die ) ).get_name() )
            elif die.tag == 'DW_TAG_class_type':
                return StructType( self._get_name( die ) )
            elif die.tag == 'DW_TAG_structure_type':
                return StructType( self._get_name( die ) )
            else:
                return UnknownType()
        except KeyError:
            return UnknownType()

    def _convert_die_to_member( self, die ):
        assert self._is_member( die ), 'die has to be a member'

        name = self._get_name( die )
        file_id = self._get_file_id( die );
        line_no = self._get_line_number( die )
        type_id = self._get_type_id( die )
        this_offset = self._get_this_offset( die )

        print( '\t%s of -%s- at %s:%d [this+%d]' \
            % ( \
                name \
                , self._decode_type_name( type_id ) \
                , self._decode_file_name( file_id ) \
                , line_no \
                , this_offset \
            ) \
        )

        member = Member()

        return member

    def _is_template( self, die ):
        return self._get_name( die ).count( '<' ) != 0

    def _is_stl( self, die ):
        return self._get_name( die ).startswith( '_' )

    def _is_local_class( self, die ):
        # todo
        return False

    def _is_base_object( self, die ):
        return die.tag == 'DW_TAG_inheritance'

    def _is_declaration( self, die ):
        return 'DW_AT_declaration' in die.attributes

    def _convert_die_to_inheritance( self, die ):
        assert self._is_base_object( die ), 'die has to be a base object (inheritance)'

        base_class_type_id = self._get_type_id( die )
        base_class_type_die = self.dies[ base_class_type_id ]
        base_class_type_name = self._get_name( base_class_type_die )

        print( '\tinheritance %s found' % base_class_type_name )

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

        struct = Struct()

        try:
            if self._skip_type( die ):
                return None

            print( 'Struct %s found' % self._get_name( die ) )

            for child in die.iter_children():
                if self._is_base_object( child ):
                    self._convert_die_to_inheritance( child )
                elif self._is_member( child ):
                    struct.add_member( self._convert_die_to_member( child ) )
        except KeyError:
            print( '\tAn error occured whilst processing, skipped' )
            return None

        except Exception:
            print( '\tAn error occured whilst processing, skipped' )
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

    def processFile( self, filename ):
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

if __name__ == "__main__":
    for fileName in sys.argv[1:]:
        cc = ClassCompacter()
        cc.processFile( fileName )
