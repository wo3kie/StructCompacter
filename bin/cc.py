# Class Compacter

import sys

sys.path.append( '..\\3rdParty\\pyelftools-0.20' );
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from elftools.common.py3compat import bytes2str

def printPrettyMap( map ):
    for k, v in map.items():
        print( "%d : %s" % ( k, v ) )


#
# IDIEType
#
class IDIEType:
    def __init__( self, dies, die ):
        self.dies = dies
        self.die = die

    def getName( self ):
        try:
            return bytes2str( self.die.attributes[ 'DW_AT_name' ].value )
        except KeyError:
            return "?"

    def typeId():
        pass

    def getDIE( self ):
        return self.die

    def getTypeId( self ):
        try:
            return self.die.attributes[ 'DW_AT_type' ].value
        except KeyError:
            return -1

    def isBasic( self ):
        return True

    def isClass( self ):
        try:
            return self.die.tag() == 'DW_TAG_structure_type' or 'DW_TAG_class_type'
        except KeyError:
            return False

    def isTemplate( self ):
        if self.isBasic():
            return False

        name = self.getName()

        leftAngleBracketCount = name.count( "<" )
        rightAngleBracketCount = name.count( ">" )

        if leftAngleBracketCount != rightAngleBracketCount:
            raise Exception( "Type name %s is not a valid template name" % name )
        elif leftAngleBracketCount == 0:
            return False
        else:
            return True

    def isInternalLibrary( self ):
        return self.getName().startswith( "_" )

    def __str__( self ):
        pass

class DIEInvalidType( IDIEType ):
    def __init__( self ):
        IDIEType.__init__( self, None, None )

    def typeId( self ):
        return "?invalid?"

    def getName( self ):
        return "?invalid?"

    def __str__( self ):
        return self.typeId()

class DIEBaseType( IDIEType ):
    def __init__( self, dies, die ):
        IDIEType.__init__( self, dies, die )

    def typeId( self ):
        return "base"

    def __str__( self ):
        return self.typeId() + " : " + self.getName()

class DIEPtrType( IDIEType ):
    def __init__( self, dies, die ):
        IDIEType.__init__( self, dies, die )

    def typeId( self ):
        return "ptr"

    def __str__( self ):
        id = self.getTypeId()

        if id == -1:
            pointedType = DIEInvalidType()
        else:
            pointedType = self.dies.get( id, DIEInvalidType() )

        return self.typeId() + " : " + str( id ) + " -> " + pointedType.getName()

class DIERefType( DIEPtrType ):
    def __init__( self, dies, die ):
        IDIEType.__init__( self, dies, die )

    def typeId( self ):
        return "ref"

class DIEArrayType( IDIEType ):
    def __init__( self, dies, die ):
        IDIEType.__init__( self, dies, die )

    def typeId( self ):
        return "array"

    def __str__( self ):
        return self.typeId() + " : " + str( self.getTypeId() )

class DIETypedef( IDIEType ):
    def __init__( self, dies, die ):
        IDIEType.__init__( self, dies, die )

    def getDIEBaseType( self ):
        return self.getTypeId()

    def typeId( self ):
        return "DIETypedef"

    def __str__( self ):
        id = self.getDIEBaseType()

        if id == -1:
            DIETypedefedType = DIEInvalidType()
        else:
            DIETypedefedType = self.dies.get( id, DIEInvalidType() )

        return self.typeId() + " : " + self.getName() + " : " + str( id ) + "\n\t" + str( DIETypedefedType )

class DIEClass( IDIEType ):
    def __init__( self, dies, die ):
        IDIEType.__init__( self, dies, die )

        self.members_skip_tags = [
              'DW_TAG_subprogram'
            , 'DW_TAG_template_type_param'
            , 'DW_TAG_template_value_param'
        ]

    def components( self ):
        for child in self.die.iter_children():
            if child.tag in self.members_skip_tags:
                continue

            if self._isStaticMember( child ):
                continue

            yield child

    def isBasic( self ):
        return False

    def typeId( self ):
        return "struct"

    def __str__( self ):
        result = self.typeId() + " : " + self.getName()

        for component in self.components():
            tag = component.tag
            elf_offset = str( component.offset )

            try:
                name = component.attributes[ "DW_AT_name" ].value.decode( "utf-8" )
            except KeyError:
                name = "(anonymous)"

            try:
                type = component.attributes[ "DW_AT_type" ].value
            except KeyError:
                type = -1

            if type == -1:
                memberType = DIEInvalidType()
            else:
                memberType = self.dies.get( type, DIEInvalidType() )

            try:
                this_offset = component.attributes[ "DW_AT_data_member_location" ].value[1]
            except KeyError:
                this_offset = "-1"

            result += '\n\t' + tag + " : " + elf_offset + " : " + name \
                + " : +" + str( this_offset ) + " : of type\n\t" + str( memberType )

        return result

    @staticmethod
    def _isStaticMember( die ):
        return 'DW_AT_external' in die.attributes

class Object:
    pass

class DIEConverter:
    def __init__( self ):
        self.dies = {}

    def process( self, dwarf_info ):
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

    def _get_name( self, die ):
        try:
            return die.attributes[ 'DW_AT_name' ].value.decode( "utf-8" )
        except KeyError:
            return "?unknown?"

    def _convert_die_to_member( self, die ):
        assert self._is_member( die ), 'die has to be a member'

        print( '\tmember %s found' % self._get_name( die ) )

    def _is_template( self, die ):
        return self._get_name( die ).count( '<' ) != 0

    def _is_stl( self, die ):
        return self._get_name( die ).startswith( '_' )

    def _is_local_class( self, die ):
        # todo
        return False
        
    def _is_base_object( self, die ):
        return die.tag == 'DW_TAG_inheritance'
        
    def _get_type_id( self, die ):
        return die.attributes[ 'DW_AT_type' ].value
        
    def _convert_die_to_base_object( self, die ):
        assert self._is_base_object( die ), 'die has to be a base object (inheritance)'
        
        base_class_type_id = self._get_type_id( die )
        base_class_type_die = self.dies[ base_class_type_id ]
        base_class_type_name = self._get_name( base_class_type_die )
        
        print( '\tinheritance %s found' % base_class_type_name )
        
        
    def _convert_die_to_class( self, die ):
        assert self._is_class( die ), 'die has to be a class type'

        print( 'Type %s found' % self._get_name( die ) )

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
            if self._is_member( child ):
                self._convert_die_to_member( child )
            elif self._is_base_object( child ):
                self._convert_die_to_base_object( child )

    def _convert_die_to_object( self, die ):
        if self._is_class( die ):
            self._convert_die_to_class( die )

    def _make_dies_mapping( self, dwarf_info ):
        for cu in dwarf_info.iter_CUs():
            top_die = cu.get_top_DIE()

            for die in top_die.iter_children():
                self.dies[ die.offset ] = die

#
# TypeFactoryImpl
#
class TypeFactoryImpl:
    def __init__( self ):
        self.TypesFactory = {}

        self.TypesFactory[ 'DW_TAG_base_type' ] = TypeFactoryImpl._createDIEBaseType

        self.TypesFactory[ 'DW_TAG_pointer_type' ] = TypeFactoryImpl._createDIEPtrType
        self.TypesFactory[ 'DW_TAG_reference_type' ] = TypeFactoryImpl._createDIERefType

        self.TypesFactory[ 'DW_TAG_array_type' ] = TypeFactoryImpl._createDIEArrayType

        self.TypesFactory[ 'DW_TAG_DIETypedef' ] = TypeFactoryImpl._createDIETypedef

        self.TypesFactory[ 'DW_TAG_structure_type' ] = TypeFactoryImpl._createDIEClass
        self.TypesFactory[ 'DW_TAG_clsss_type' ] = TypeFactoryImpl._createDIEClass

    def create( self, dies, die ):
        return self.TypesFactory[ die.tag ]( self, dies, die )

    def types( self ):
        return self.TypesFactory.keys()

    @staticmethod
    def _createDIEBaseType( self, dies, die ):
        return DIEBaseType( dies, die )

    @staticmethod
    def _createDIETypedef( self, dies, die ):
        return DIETypedef( dies, die )

    @staticmethod
    def _createDIEClass( self, dies, die ):
        return DIEClass( dies, die )

    @staticmethod
    def _createDIEPtrType( self, dies, die ):
        return DIEPtrType( dies, die )

    @staticmethod
    def _createDIERefType( self, dies, die ):
        return DIERefType( dies, die )

    @staticmethod
    def _createDIEArrayType( self, dies, die ):
        return DIEArrayType( dies, die )

class TypeFactory:
    def __init__( self ):
        self.instance = None

    def get( self ):
        if not self.instance:
            self.instance = TypeFactoryImpl()

        return self.instance

    def types( self ):
        return self.get().types()

class Var:
    pass

class Class( Var ):
    def __init__( self ):
        pass

class Inheritance( Var ):
    def __init__( self ):
        pass

class Member( Var ):
    def __init__( self ):
        pass

def isMember( die ):
    if die.tag() == 'DW_TAG_member':
        return False

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

    def __processDWARF( self, elfFile ):
        if not elfFile.has_dwarf_info():
            print( "File %s has no DWARF info" % fileName )
            return

        dwarfInfo = elfFile.get_dwarf_info()

        for cu in dwarfInfo.iter_CUs():
            topDIE = cu.get_top_DIE()
            self._processDIERecursively( topDIE )

        for k, v in self.dies.items():
            if v.isBasic() == True:
                continue

            if v.isTemplate() == True:
                continue

            #if v.isInternalLibrary():
            #    continue

            print( "%d : %s" % ( k, v ) )

    def _processDIERecursively( self, die ):
        if die.tag in TypeFactory().get().types():
            self.dies[ die.offset ] = TypeFactory().get().create( self.getDIEs(), die )

        for child in die.iter_children():
            self._processDIERecursively( child )

if __name__ == "__main__":
    for fileName in sys.argv[1:]:
        cc = ClassCompacter()
        cc.processFile( fileName )
