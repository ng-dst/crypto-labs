class MacInterface:
    """ Main interface for MACs """

    def setKey(self, key: bytes) -> None:
        """ MAC key setter """
        ...

    def addBlock(self, block: bytes) -> None:
        """ Update MAC state with a new data block """
        ...

    def finalize(self) -> bytes:
        """ Return the resultant auth code for previously given data """
        ...

    def computeMac(self, data: bytes) -> bytes:
        """ Compute auth code for arbitrary data """
        ...

    def verifyMac(self, data: bytes, tag: bytes) -> bool:
        """ Verify auth code (True / False depending on validity) """
        ...
