# Class Compacter

import sys

sys.path.append( '..\\3rdParty\\pyelftools-0.20' );
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from elftools.common.py3compat import bytes2str

def printPrettyMap( map ):
    for k, v in map.items():
        print( "%d : %s" % ( k, v ) )

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
    def get_name( self ):
        pass

    def get_size( self ):
        pass

class UnknownType( Type ):
    def get_name( self ):
        return "unknown"

    def get_size( self ):
        return -1

class PtrType( Type ):
    def __init__( self, size = 4 ):
        self.size = size

    def get_name( self ):
        return "ptr"

    def get_size( self ):
        return self.size

class BaseType( Type ):
    def __init__( self, name, size ):
        self.name = name
        self.size = size

    def get_name( self ):
        return self.name

    def get_size( self ):
        return self.size

class DIEConverter:
    def __init__( self ):
        self.dies = {}
        self.ptr_size = 4

    def process( self, dwarf_info ):
        self._ptr_size = self._get_ptr_size( dwarf_info )

        self._make_dies_mapping( dwarf_info )

        self._convert_dwarf_to_objects( dwarf_info )

    def _convert_dwarf_to_objects( self, dwarf_info ):
        for cu in dwarf_info.iter_CUs():
            self._convert_CU_to_objects( cu )

    def _convert_CU_to_objects( self, cu ):
        top_die = cu.get_top_DIE()

        for die in top_die.iter_children():
            self._convert_die_to_object( die )

    def _is_class( self, die ):
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

    def _get_name( self, die ):
        try:
            return die.attributes[ 'DW_AT_name' ].value.decode( 'utf-8' )
        except KeyError:
            return '?no type name?'

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
        try:
            return die.attributes[ 'DW_AT_decl_line' ].value
        except KeyError:
            return -1

    def _get_type_id( self, die ):
        try:
            return die.attributes[ 'DW_AT_type' ].value
        except KeyError:
            return -1

    def _get_this_offset( self, die ):
        try:
            return die.attributes[ 'DW_AT_data_member_location' ].value[1]
        except KeyError:
            return -1

    def _decode_type_name( self, type_id ):
        try:
            return self._resolve_type( type_id ).get_name()
        except KeyError:
            return 'unknown type_id'

    def _decode_file_name( self, file_id ):
        return 'main.cpp'

    def _resolve_type( self, type_id ):
        try:
            die = self.dies[ type_id ]

            if die.tag == 'DW_TAG_pointer_type':
                return PtrType( self._ptr_size )
            elif die.tag == 'DW_TAG_base_type':
                return BaseType( self._get_name( die ), self._get_size( die ) )
            else:
                return UnknownType()
        except KeyError:
            return UnknownType()

    def _convert_die_to_member( self, die ):
        assert self._is_member( die ), 'die has to be a member'

        file_id = self._get_file_id( die );
        line_no = self._get_line_number( die )
        name = self._get_name( die )
        type_id = self._get_type_id( die )
        this_offset = self._get_this_offset( die )

        print( '\t%s of %s at %s:%d [this+%d]' \
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

    def _convert_die_to_inheritance( self, die ):
        assert self._is_base_object( die ), 'die has to be a base object (inheritance)'

        base_class_type_id = self._get_type_id( die )
        base_class_type_die = self.dies[ base_class_type_id ]
        base_class_type_name = self._get_name( base_class_type_die )

        print( '\tinheritance %s found' % base_class_type_name )


    def _convert_die_to_type( self, die ):
        assert self._is_class( die ), 'die has to be a class type'

        print( 'Struct %s found' % self._get_name( die ) )

        struct = Struct()

        if self._is_stl( die ):
            print( '\tSTL skipped' )
            return None

        if self._is_template( die ):
            print( '\ttemplate skipped' )
            return None

        if self._is_local_class( die ):
            print( '\tlocal class skipped' )
            return None

        for child in die.iter_children():
            if self._is_base_object( child ):
                self._convert_die_to_inheritance( child )
            elif self._is_member( child ):
                struct.add_member( self._convert_die_to_member( child ) )

        return struct

    def _convert_die_to_object( self, die ):
        if self._is_class( die ):
            self._convert_die_to_type( die )

    def _make_dies_mapping( self, dwarf_info ):
        for cu in dwarf_info.iter_CUs():
            top_die = cu.get_top_DIE()

            for die in top_die.iter_children():
                self.dies[ die.offset ] = die

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
