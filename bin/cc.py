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

class DIEStruct( IDIEType ):
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

        self.TypesFactory[ 'DW_TAG_structure_type' ] = TypeFactoryImpl._createDIEStruct
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
    def _createDIEStruct( self, dies, die ):
        return DIEStruct( dies, die )

    @staticmethod
    def _createDIEClass( self, dies, die ):
        return self._createDIEStruct( dies, die )

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
