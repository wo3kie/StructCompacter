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
# IType
#
class IType:
    def __init__( self, die ):
        self.die = die

    @staticmethod
    def getName( die ):
        try:
            return bytes2str( die.attributes[ 'DW_AT_name' ].value )
        except KeyError:
            return "?"

    def getType( die ):
        try:
            return die.attributes[ 'DW_AT_type' ].value
        except KeyError:
            return -1

class BaseType( IType ):
    def __init__( self, die ):
        IType.__init__( self, die )

    def __str__( self ):
        return "base: " + self.getName( self.die )

class PtrType( IType ):
    def __init__( self, die ):
        IType.__init__( self, die )

    def __str__( self ):
        return "ptr: " + str( IType.getType( self.die ) )

class RefType( IType ):
    def __init__( self, die ):
        IType.__init__( self, die )

    def __str__( self ):
        return "ref: " + str( IType.getType( self.die ) )

class ArrayType( IType ):
    def __init__( self, die ):
        IType.__init__( self, die )

    def __str__( self ):
        return "Array: " + str( IType.getType( self.die ) )

class Typedef( IType ):
    def __init__( self, die ):
        IType.__init__( self, die )

    def getBaseType( self ):
        return IType.getType( self.die )

    def __str__( self ):
        return "typedef: " + self.getName( self.die ) + " -> " + str( self.getBaseType() )

class Struct( IType ):
    def __init__( self, die ):
        IType.__init__( self, die )

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

    def isTemplate( self ):
        name = self.getName()

        leftAngleBracketCount = name.count( "<" )
        rightAngleBracketCount = name.count( ">" )

        if leftAngleBracketCount != rightAngleBracketCount:
            raise Exception( "Type name %s is not a valid template name" % name )
        elif leftAngleBracketCount == 0:
            return False
        else:
            return True

    @staticmethod
    def _isStaticMember( die ):
        return 'DW_AT_external' in die.attributes

    def __str__( self ):
        result = "struct: " + self.getName( self.die )

        for component in self.components():
            tag = component.tag
            offset = str( component.offset )

            try:
                name = component.attributes[ "DW_AT_name" ].value.decode( "utf-8" )
            except KeyError:
                name = "(anonymous)"

            try:
                type = component.attributes[ "DW_AT_type" ].value
            except KeyError:
                type = -1

            result += '\n\t' + tag + " : " + offset + " : " + name + " : of type " + str( type )

        return result

#
# TypeFactoryImpl
#
class TypeFactoryImpl:
    def __init__( self ):
        self.TypesFactory = {}

        self.TypesFactory[ 'DW_TAG_base_type' ] = TypeFactoryImpl._createBaseType

        self.TypesFactory[ 'DW_TAG_pointer_type' ] = TypeFactoryImpl._createPtrType
        self.TypesFactory[ 'DW_TAG_reference_type' ] = TypeFactoryImpl._createRefType

        self.TypesFactory[ 'DW_TAG_array_type' ] = TypeFactoryImpl._createArrayType

        self.TypesFactory[ 'DW_TAG_typedef' ] = TypeFactoryImpl._createTypedef

        self.TypesFactory[ 'DW_TAG_structure_type' ] = TypeFactoryImpl._createStruct
        self.TypesFactory[ 'DW_TAG_clsss_type' ] = TypeFactoryImpl._createClass

    def create( self, die ):
        return self.TypesFactory[ die.tag ]( self, die )

    def types( self ):
        return self.TypesFactory.keys()

    @staticmethod
    def _createBaseType( self, die ):
        return BaseType( die )

    @staticmethod
    def _createTypedef( self, die ):
        return Typedef( die )

    @staticmethod
    def _createStruct( self, die ):
        return Struct( die )

    @staticmethod
    def _createClass( self, die ):
        return self._createStruct( die )

    @staticmethod
    def _createPtrType( self, die ):
        return PtrType( die )

    @staticmethod
    def _createRefType( self, die ):
        return RefType( die )

    @staticmethod
    def _createArrayType( self, die ):
        return ArrayType( die )

class TypeFactory:
    def __init__( self ):
        self.instance = None

    def get( self ):
        if not self.instance:
            self.instance = TypeFactoryImpl()

        return self.instance

    def types( self ):
        return self.get().types()

#
# ClassCompacter
#
class ClassCompacter:
    def __init__( self ):
        self.dies = {}

    def processFile( self, filename ):
        with open( fileName, 'rb' ) as file:
            try:
                elfFile = ELFFile( file )
            except ELFError:
                print( "Could not open ELF file: %s" % fileName )
                return

            self._processDWARF( elfFile )

    def _processDWARF( self, elfFile ):
        if not elfFile.has_dwarf_info():
            print( "File %s has no DWARF info" % fileName )
            return

        dwarfInfo = elfFile.get_dwarf_info()

        for cu in dwarfInfo.iter_CUs():
            topDIE = cu.get_top_DIE()
            self._processDIERecursively( topDIE )

        printPrettyMap( self.dies )

    def _processDIERecursively( self, die ):
        if die.tag in TypeFactory().get().types():
            self.dies[ die.offset ] = TypeFactory().get().create( die )

        for child in die.iter_children():
            self._processDIERecursively( child )

if __name__ == "__main__":
    for fileName in sys.argv[1:]:
        cc = ClassCompacter()
        cc.processFile( fileName )
