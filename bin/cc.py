# Class Compacter

import sys

sys.path.append( '..\\3rdParty\\pyelftools-0.20' );
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from elftools.common.py3compat import bytes2str

def isTemplateName( name ):
    assert len( name ) > 0

    leftAngleBracketCount = name.count( "<" )
    rightAngleBracketCount = name.count( ">" )

    if leftAngleBracketCount != rightAngleBracketCount:
        raise Exception( "Type name %s is not a valid template name" % name )
    elif leftAngleBracketCount == 0:
        return False
    else:
        return True

def printPrettyMap( map ):
    for k, v in map.items():
        print( "%d : %s" % ( k, v ) )
        
        
#
# IType
#
class IType:
    def __init__( self, die ):
        self.die = die

    def getName( self, die ):
        return bytes2str( die.attributes[ 'DW_AT_name' ].value )

class BaseType( IType ):
    def __init__( self, die ):
        IType.__init__( self, die )

    def __str__( self ):
        return "base: " + self.getName( self.die )

class Typedef( IType ):
    def __init__( self, die ):
        IType.__init__( self, die )

    def __str__( self ):
        return "typedef: " + self.getName( self.die )

class Struct( IType ):
    def __init__( self, die ):
        IType.__init__( self, die )

    def __str__( self ):
        return "struct: " + self.getName( self.die )

class Class( IType ):
    def __init__( self, die ):
        IType.__init__( self, die )

    def __str__( self ):
        return "class: " + self.getName( self.die )

#
# TypeFactoryImpl
#
class TypeFactoryImpl:
    def __init__( self ):
        self.TypesFactory = {}

        self.TypesFactory[ 'DW_TAG_base_type' ] = TypeFactoryImpl._createBase
        self.TypesFactory[ 'DW_TAG_typedef' ] = TypeFactoryImpl._createTypedef
        self.TypesFactory[ 'DW_TAG_structure_type' ] = TypeFactoryImpl._createStruct
        self.TypesFactory[ 'DW_TAG_clsss_type' ] = TypeFactoryImpl._createClass

    def create( self, die ):
        return self.TypesFactory[ die.tag ]( self, die )

    def types( self ):
        return self.TypesFactory.keys()

    @staticmethod
    def _createBase( self, die ):
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
            #print( TypeFactory().get().create( die ) )
            
            self.dies[ die.offset ] = TypeFactory().get().create( die )

        for child in die.iter_children():
            self._processDIERecursively( child )

if __name__ == "__main__":
    for fileName in sys.argv[1:]:
        cc = ClassCompacter()
        cc.processFile( fileName )
