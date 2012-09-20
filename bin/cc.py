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

    def getTypeId( self ):
        try:
            return self.die.attributes[ 'DW_AT_type' ].value
        except KeyError:
            return -1

    def isBasic( self ):
        return True

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

class InvalidType( IType ):
    def __init__( self ):
        IType.__init__( self, None, None )

    def typeId( self ):
        return "?invalid?"

    def getName( self ):
        return "?invalid?"

    def __str__( self ):
        return self.typeId()

class BaseType( IType ):
    def __init__( self, dies, die ):
        IType.__init__( self, dies, die )

    def typeId( self ):
        return "base"

    def __str__( self ):
        return self.typeId() + " : " + self.getName()

class PtrType( IType ):
    def __init__( self, dies, die ):
        IType.__init__( self, dies, die )

    def typeId( self ):
        return "ptr"

    def __str__( self ):
        id = self.getTypeId()

        if id == -1:
            pointedType = InvalidType()
        else:
            pointedType = self.dies.get( id, InvalidType() )

        return self.typeId() + " : " + str( id ) + " -> " + pointedType.getName()

class RefType( PtrType ):
    def __init__( self, dies, die ):
        IType.__init__( self, dies, die )

    def typeId( self ):
        return "ref"

class ArrayType( IType ):
    def __init__( self, dies, die ):
        IType.__init__( self, dies, die )

    def typeId( self ):
        return "array"

    def __str__( self ):
        return self.typeId() + " : " + str( self.getTypeId() )

class Typedef( IType ):
    def __init__( self, dies, die ):
        IType.__init__( self, dies, die )

    def getBaseType( self ):
        return self.getTypeId()

    def typeId( self ):
        return "typedef"

    def __str__( self ):
        id = self.getBaseType()

        if id == -1:
            typedefedType = InvalidType()
        else:
            typedefedType = self.dies.get( id, InvalidType() )

        return self.typeId() + " : " + self.getName() + " : " + str( id ) + "\n\t" + str( typedefedType )

class Struct( IType ):
    def __init__( self, dies, die ):
        IType.__init__( self, dies, die )

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
                memberType = InvalidType()
            else:
                memberType = self.dies.get( type, InvalidType() )

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

    def create( self, dies, die ):
        return self.TypesFactory[ die.tag ]( self, dies, die )

    def types( self ):
        return self.TypesFactory.keys()

    @staticmethod
    def _createBaseType( self, dies, die ):
        return BaseType( dies, die )

    @staticmethod
    def _createTypedef( self, dies, die ):
        return Typedef( dies, die )

    @staticmethod
    def _createStruct( self, dies, die ):
        return Struct( dies, die )

    @staticmethod
    def _createClass( self, dies, die ):
        return self._createStruct( dies, die )

    @staticmethod
    def _createPtrType( self, dies, die ):
        return PtrType( dies, die )

    @staticmethod
    def _createRefType( self, dies, die ):
        return RefType( dies, die )

    @staticmethod
    def _createArrayType( self, dies, die ):
        return ArrayType( dies, die )

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

    def getDIEs( self ):
        return self.dies

    def _processDWARF( self, elfFile ):
        if not elfFile.has_dwarf_info():
            print( "File %s has no DWARF info" % fileName )
            return

        dwarfInfo = elfFile.get_dwarf_info()

        for cu in dwarfInfo.iter_CUs():
            topDIE = cu.get_top_DIE()
            self._processDIERecursively( topDIE )

        for k, v in self.dies.items():
            #if v.isBasic() == True:
            #    continue

            #if v.isTemplate() == True:
            #    continue

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
