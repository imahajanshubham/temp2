import re
import utils

#import STB_LIBRARY
#from STB_LIBRARY import STB_Library_Core
import COMMON
#from COMMON.CRYPTO_INTERFACE import CRYPTO_INTERFACE
from COMMON.READER_INTERFACE import READER_INTERFACE

class TAG:
    FCP                         = "62"
    FID                         = "83"
    FDB                         = "82"
    FILE_SIZE                   = "80"
    SFID                        = "88"
    LCS                         = "8A"
    SECURITY                    = "8C"
    SE_ID                      = "8D"
    SE_TEMPLATE                 = "7B"


class CLA:
    NO_SEC_MSG                  = '00'
    SM_WITH_AUTH                = "0C"
    SM_NO_AUTH                  = "08"


class INS:
    # ======================================================================== #
    # Basic INS                                                                #
    # ======================================================================== #

    CREATE_FILE                 = 'E0'
    DELETE_FILE                 = "E4"
    SELECT_FILE                 = "A4"
    ACTIVATE_FILE               = "44"
    DEACTIVATE_FILE             = "04"
    TERMINATE_DF                = "E6"
    TERMINATE_EF                = "E8"
    TERMINATE_CARD              = "FE"

    # ======================================================================== #
    # Data Modification Related INS                                            #
    # ======================================================================== #

    READ_BINARY                 = "B0"
    READ_RECORD                 = "B2"
    WRITE_BINARY                = "D0"
    WRITE_RECORD                = "D2"
    UPDATE_BINARY               = "D6"
    UPDATE_RECORD               = "DC"
    APPEND_RECORD               = "E2"
    ERASE_BINARY                = "0E"

    # ======================================================================== #
    # Security Related INS                                                     #
    # ======================================================================== #

    VERIFY                      = "20"
    GET_CHALLENGE               = "84"
    INTERNAL_AUTH               = "88"
    EXTERNAL_AUTH               = "82"
    MUTUAL_AUTHENTICATION       = "82"
    CHANGE_REFERENCE_DATA       = "24"
    RESET_RETRY_COUNTER         = "2C"
    MANAGE_SEC_ENV              = "22"  # TODO
    PSO                         = "2A"  # TODO
    ENABLE_VERIFICATION_REQ     = "28"  # TODO
    DISABLE_VERIFICATION_REQ    = "26"  # TODO
    MSE                         = "22"

    # ======================================================================== #
    # Other INS                                                                #
    # ======================================================================== #

    GET_DATA                    = "CA"
    PUT_DATA                    = "DA"
    GET_RESPONSE                = "C0"

class STATUS:
    sw1sw2 = {
            #Warnings
                "6200" : "No Information given",
                "6202" : "Triggering by the card (see 8.6.1 7816-4)",
                "6281" : "Part of returned data may be corrupted",
                "6282" : "End of file or record reached before reading Ne bytes",
                "6283" : "Selected file deactivated",
                "6284" : "File control information not formatted according to 5.3.3",
                "6285" : "Selected file in termination state",
                "6286" : "No input data available from a sensor on the card",
                "6300" : "No information given",
                "6381" : "File filled up by the last write",

                #Error
                "6500" : "No information given",
                "6581" : "Memory failure",
                "6800" : "No information given",
                "6881" : "Logical channel not supported",
                "6882" : "Secure messaging not supported",
                "6883" : "Last command of the chain expected",
                "6884" : "Command chaining not supported",

                "6a80" : "Incorrect parameters in the command",
                "6a82" : "File/Application not found",
                "6a84" : "Not enough memory",
                "6a89" : "File Already exist",
                "9000" : "Successful"
            }


class SCOSTA:
    # ======================================================================== #
    # GET LENGTH                                                               #
    # ======================================================================== #

    def getLength(data, byteSize = 1):
        """
        Returns the length of the data in HEX String.

        Parameters:
            data                (Variable, Mand.):   Input data in String
            byteSize            (Variable, Mand.):   Data length in Bytes.

        Returns:
            hexValueInString    (Variable Size):   Calculated Length.
        """
        hexValueInString = format((int)((len(data) - data.count(' ')) / 2), 'x')
        return hexValueInString.zfill(2 * byteSize)


    # ======================================================================== #
    # CONVERT DECIMAL TO HEX STRING                                            #
    # ======================================================================== #

    def convertDecToHexString(data, byteSize = 1):
        """
        Returns the converted HEX Value of input data.

        Parameters:
            data                (Variable, Mand.):   Input data in String
            byteSize            (Variable, Mand.):   Data length in Bytes.

        Returns:
            format    (Variable Size):   Calculated Length.
        """

        return format(data, 'x').zfill(2 * byteSize)

    def generateSFID(rawSFID):
        msb = str(format(rawSFID >> 1, 'x'))
        lsb = str(format(((rawSFID & 1) << 3), 'x'))
        return msb + lsb


    def readBinary(length = "00", p1 = "00", p2 = "00"):
        header = CLA.NO_SEC_MSG + INS.READ_BINARY + p1 + p2
        le = length
        apdu = header + le
        return READER_INTERFACE().sendRawAPDU(apdu)


    def readRecord(length = "00", p1 = "00", p2 = "00"):
        header = CLA.NO_SEC_MSG + INS.READ_RECORD + p1 + p2
        le = length
        apdu = header + le
        return READER_INTERFACE().sendRawAPDU(apdu)

    def writeBinary(data = "", p1 = "00", p2 = "00",length = "00"):
        header = CLA.NO_SEC_MSG + INS.WRITE_BINARY + p1 + p2
        if(length == "00"):
            lc = SCOSTA.getLength(data)
        else:
            lc = length
        apdu = header + lc + data
        return READER_INTERFACE().sendRawAPDU(apdu)

    # ======================================================================== #
    # WRITE RECORD                                                             #
    # ======================================================================== #

    def writeRecord(recordData, p1 = "01", p2 = "04", recordLen = "00"):
        byteSize    = 1

        # ------------------------------------------------------ Generate Header
        header      = CLA.NO_SEC_MSG + INS.WRITE_RECORD + p1 + p2

        if(recordLen == "00"):
            lc = SCOSTA.getLength(recordData)
        else:
            lc = recordLen

        # -------------------------------------------------------- Generate Data
        data        = recordData

        apdu        = header + lc + data
        return READER_INTERFACE().sendRawAPDU(apdu)


    def updateBinary(data = "", p1 = "00", p2 = "00", length = "00"):
        header = CLA.NO_SEC_MSG + INS.UPDATE_BINARY + p1 + p2
        if(length == "00"):
            lc = SCOSTA.getLength(data)
        else:
            lc = length
        apdu = header + lc + data
        return READER_INTERFACE().sendRawAPDU(apdu)


    def updateRecord(data = "", p1 = "00", p2 = "00", length = "00"):
        header = CLA.NO_SEC_MSG + INS.UPDATE_RECORD + p1 + p2
        if(length == "00"):
            lc = SCOSTA.getLength(data)
        else:
            lc = length
        apdu = header + lc + data
        return READER_INTERFACE().sendRawAPDU(apdu)


    def appendRecord(p2 = "00", data = "", length = "00"):
        header = CLA.NO_SEC_MSG + INS.APPEND_RECORD + p1 + p2
        if(length == "00"):
            lc = SCOSTA.getLength(data)
        else:
            lc = length
        apdu = header + lc + data
        return READER_INTERFACE().sendRawAPDU(apdu)


    def eraseBinary(data = "", p1 = "00", length = "00"):
        header = CLA.NO_SEC_MSG + INS.APPEND_RECORD + p1 + p2
        if(length == "00"):
            lc = SCOSTA.getLength(data)
        else:
            lc = length
        apdu = header + lc + data
        return READER_INTERFACE().sendRawAPDU(apdu)


    # ======================================================================== #
    # CREATE DF                                                                #
    # ======================================================================== #

    def createDF(fID,  p1 = '00', p2 = '00', seID = None, seTemplate = None):
        # ------------------------------------------------------ Generate Header
        header      = CLA.NO_SEC_MSG + INS.CREATE_FILE + p1 + p2
        byteSize    = 1

        # --------------------------------------------------------- Generate FCP
        fID_Len     = SCOSTA.getLength(fID, byteSize)
        fcpValue    = TAG.FDB + "0138" + TAG.FID + fID_Len + fID
        if seID != None:
            fcpValue += TAG.SE_ID + SCOSTA.getLength(seID, byteSize) + seID

        if seTemplate != None:
            fcpValue += TAG.SE_TEMPLATE + SCOSTA.getLength(seTemplate, byteSize) + seTemplate


        fcpLen      = SCOSTA.getLength(fcpValue, byteSize)

        # ------------------------------------------------------   Generate Data
        data        = TAG.FCP + fcpLen + fcpValue
        #lc          = (int)((len(data) - data.count(' ')) / 2)
        lc          = SCOSTA.getLength(data, byteSize)
        #data = re.sub(r"\s+", "", data)
        apdu        = header + lc + data
        return READER_INTERFACE().sendRawAPDU(apdu)
        #SW = STB_Library_Core.Send_Apdu(CLA.NO_SEC_MSG, INS.CREATE_FILE, p1, p2, lc, data)


##    def createDFWithSE(fID, sefID, p1 = "00", p2 = "00"):
##        """
##        APDU for Create DF with Security Environment File in it.
##        INS = E0.
##        Creates a minimal DF in the current context.
##
##        Parameters:
##            fID     (2 Bytes, Mand.):   File ID.
##            sefID   (1 Byte, Mand.):    Security Environment File ID.
##
##        Returns:
##            apdu    (Variable Size):    Generated APDU.
##        """
##
##        # ------------------------------------------------------ Generate Header
##        header          = CLA.NO_SEC_MSG + INS.CREATE_FILE + p1 + p2
##        byteSize        = 1
##
##        # ------------------------------------- Generate FCP and include SE File
##        sefID_Len       = SCOSTA.getLength(sefID, byteSize)
##        seFile          = "8D" + sefID_Len + sefID
##        fID_Len         = SCOSTA.getLength(fID, byteSize)
##        fcpValue        = TAG.FDB + "0138" + TAG.FID + fID_Len + fID + seFile;
##        fcpLen          = SCOSTA.getLength(fcpValue, byteSize)
##
##        # -------------------------------------------------------- Generate Data
##        data         = TAG.FCP + fcpLen + fcpValue
##        lc           = SCOSTA.getLength(data, byteSize)
##
##        apdu         = header + lc + data
##        return READER_INTERFACE().sendRawAPDU(apdu)

    # ======================================================================== #
    # CREATE SE FILE WITH SECURITY                                             #
    # ======================================================================== #

    def createRecordFile(fID = "", sfID = None, fdb = "0C", recordLen = "0020", noOfRecords = "10", dataCodingByte = "01", accessModeByte = None, p1 = "00", p2 = "00", lcsByte = "05"):
        """
        APDU for Create EF with Record Contents.
        INS = E0.
        Creates a Secure EF.

        Parameters:
            fID             (2 Bytes, Mand.):   File ID.
            sfID            (1 Byte, Opt.):     Short File ID.
                                                    NOTE: sfID is mandatory for creating SE-Record File,
                                                        PIN File (sfID = 01),
                                                        KEY File (sfID = 02).
            recordType      (1 Byte, Opt.):     Variable ("0C") Size,
                                                    Fixed ("0A") Size,
                                                    Default = "0C".
            recordLen       (2 Bytes, Opt.):    (Default = "0020").
            noOfRecords     (1 Byte, Opt.):     (Default = "10").
            accessModeByte  (1 Byte, Opt.):     Access Mode Byte (TABLE 17/5.4.3.1),
                                                    (Default = "78" i.e. read + update + write & no conditions).
            scbDelete       (1 Byte, Opt.):     Delete File Opteration,
                                                    (Default ="00").
            scbTerminate    (1 Byte, Opt.):     Terminate File Operation,
                                                    (Default = "00").
            scbActivate     (1 Byte, Opt.):     Activate File,
                                                    (Default = "00").
            scbDeactivate   (1 Byte, Opt.)      De-activate File Operation,
                                                    (Default = "00").
            scbWrite        (1 Byte, Opt.):     Write Operation,
                                                    (Default = "FF").
            scbUpdate       (1 Byte, Opt.):     Update File operation,
                                                    (Default = "FF").
            scbRead         (1 Byte, Opt.):     Readd File operation,
                                                    (Default = "FF").
            p1              (1 Byte, Opt.):     (Default = "00").
            p2              (1 Byte, Opt.):     (Default = "00").

        Returns:
            apdu (string):  Generated APDU.
        """

        byteSize        = 1

        # ------------------------------------------------------ Generate Header
        header          = CLA.NO_SEC_MSG + INS.CREATE_FILE + p1 + p2

        # ------------------------------------------------- Generate Record Data
        recordData      = fdb + dataCodingByte + recordLen + noOfRecords
        # FIXME: record size is of 2 bytes instead of 1.
        recordDataLen   = SCOSTA.getLength(recordData, byteSize)
        # --------------------------------------------------------- Generate LCI
        lcsData         = "8A01" + lcsByte

        # --------------------------------------------------------- Generate FCP
        fID_Len     = SCOSTA.getLength(fID, byteSize)

        fcpValue    = TAG.FID + fID_Len + fID + lcsData + TAG.FDB + recordDataLen + recordData

        if(accessModeByte != None):
            fcpValue += TAG.SECURITY + SCOSTA.getLength(accessModeByte, byteSize) + accessModeByte

        if sfID is not None:
            sfID_Len    = SCOSTA.getLength(sfID, byteSize)
            fcpValue    = fcpValue + TAG.SFID + sfID_Len + sfID

        fcpLen      = SCOSTA.getLength(fcpValue, byteSize)

        # -------------------------------------------------------- Generate Data
        data        = TAG.FCP + fcpLen + fcpValue
        lc          = SCOSTA.getLength(data, byteSize)

        apdu        = header + lc + data
        return READER_INTERFACE().sendRawAPDU(apdu)


    def createBinaryFile(fID, fileSize = "0000", fdb = "01", dataCodingByte = "01", sfID = None, lcsByte = "05", accessModeByte = None, p1 = "00", p2 = "00"):
        header = CLA.NO_SEC_MSG + INS.CREATE_FILE + p1 + p2

        fID_Len = SCOSTA.getLength(fID)

        lcsLen = SCOSTA.getLength(lcsByte)

        fdbLen = SCOSTA.getLength(fdb + dataCodingByte)

        fileSizeLen = SCOSTA.getLength(fileSize, 1)
        fID_Len = SCOSTA.getLength(fID)
        #TAG.SECURITY + secDataLen + secData

        fcpValue = TAG.FID + fID_Len + fID + TAG.FDB + fdbLen + fdb + dataCodingByte + TAG.LCS + lcsLen + lcsByte + TAG.FILE_SIZE + fileSizeLen + fileSize

        if(accessModeByte != None):
            fcpValue += TAG.SECURITY + SCOSTA.getLength(accessModeByte, byteSize) + accessModeByte

        if sfID is not None:
            sfID_Len = SCOSTA.getLength(sfID)
            fcpValue = fcpValue + TAG.SFID + sfID_Len + sfID

        fcpLen = SCOSTA.getLength(fcpValue)

        data = TAG.FCP + fcpLen + fcpValue
        lc = SCOSTA.getLength(data)

        apdu = header + lc + data

        return READER_INTERFACE().sendRawAPDU(apdu)


    # ======================================================================== #
    # DELETE FILE                                                              #
    # ======================================================================== #

    def deleteFile(fID = "", p1 = "00", p2 = "00"):
        """
        APDU to delete a file using its FID.
        INS = E4.

        Parameters:
            fID     (2 Bytes, Mand.):   File ID.
            p1      (1 Byte, Opt.):     Parameter 1,
                                            (Default = "00").
            p2      (1 Byte, Opt.):     Parameter 2,
                                            (Default = "00").

        Returns:
            apdu    (Variable Size):    Generated APDU.
        """

        # ------------------------------------------------------ Generate Header
        header      = CLA.NO_SEC_MSG + INS.DELETE_FILE + p1 + p2

        # -------------------------------------------------------- Generate Data
        data        = fID
        lc          = SCOSTA.getLength(data, 1)

        apdu        = header + lc + data
        return READER_INTERFACE().sendRawAPDU(apdu)


    # ======================================================================== #
    # SELECT FILE                                                              #
    # ======================================================================== #

    def selectFile(fID, p1 = "00", p2 = "00"):
        """
        APDU to select a file using its FID.
        INS = A4.

        Parameters:
            fID     (2 Bytes, Mand.):   File ID.
            p1      (1 Byte, Opt.):     Parameter 1,
                                            (Default = "00").
            p2      (1 Byte, Opt.):     Parameter 2,
                                            (Default = "00").

        Returns:
            apdu    (Variable Size):    Generated APDU.
        """

        # ------------------------------------------------------ Generate Header
        header      = CLA.NO_SEC_MSG + INS.SELECT_FILE + p1 + p2

        # -------------------------------------------------------- Generate Data
        data        = fID
        lc          = SCOSTA.getLength(data, 1)

        apdu        = header + lc + data
        return READER_INTERFACE().sendRawAPDU(apdu)


    def activateFile(fID = "", p1 = "00", p2 = "00"):
        header = CLA.NO_SEC_MSG + INS.ACTIVATE_FILE + p1 + p2
        data = fID
        lc = SCOSTA.getLength(data, 1)
        apdu = header + lc + data
        return READER_INTERFACE().sendRawAPDU(apdu)


    def deactivate(fID = "", p1 = "00", p2 = "00"):
        header = CLA.NO_SEC_MSG + INS.DEACTIVATE_FILE + p1 + p2
        data = fID
        lc = SCOSTA.getLength(data, 1)
        apdu = header + lc + data
        return READER_INTERFACE().sendRawAPDU(apdu)


    def terminateDF(fID = "", p1 = "00", p2 = "00"):
        header = CLA.NO_SEC_MSG + INS.TERMINATE_DF + p1 + p2
        data = fID
        lc = SCOSTA.getLength(data, 1)
        apdu = header + lc + data
        return READER_INTERFACE().sendRawAPDU(apdu)


    def terminateEF(fID = "", p1 = "00", p2 = "00"):
        header = CLA.NO_SEC_MSG + INS.TERMINATE_EF + p1 + p2
        data = fID
        lc = SCOSTA.getLength(data, 1)
        apdu = header + lc + data
        return READER_INTERFACE().sendRawAPDU(apdu)


    def terminateCard():
        header = CLA.NO_SEC_MSG + INS.TERMINATE_CARD + "00" + "00"
        apdu = header
        return READER_INTERFACE().sendRawAPDU(apdu)


    def verify(p2 = "00", data = "", length = "00", p1 = "00"):
        header = CLA.NO_SEC_MSG + INS.VERIFY + p1 + p2
        if(length == "00"):
            lc = SCOSTA.getLength(data)
        else:
            lc = length
        apdu = header + lc + data
        return READER_INTERFACE().sendRawAPDU(apdu)


    def internalAuth(data = "11 22 33 44 55 66 77 88", p1 = "00", p2 = "00"):
        header = CLA.NO_SEC_MSG + INS.INTERNAL_AUTH + p1 + p2
        lc = SCOSTA.getLength(data)
        apdu = header + lc + data
        return READER_INTERFACE().sendRawAPDU(apdu)


    def externalAuth(data = "", key = "11 22 33 44 55 66 77 88", p1 = "00", p2 = "00"):
        encrypted_Data = CRYPTO.DES_COMPUTE_3DES_CBC(data, key)
        header = CLA.NO_SEC_MSG + INS.EXTERNAL_AUTH + p1 + p2
        data = encrypted_Data
        lc = SCOSTA.getLength(data)
        apdu = header + lc + data
        return READER_INTERFACE().sendRawAPDU(apdu)


    # ======================================================================== #
    # GET CHALLENGE                                                            #
    # ======================================================================== #

    def getChallenge(randDataSize = "00"):
        # ------------------------------------------------------ Generate Header
        p1          = "00"
        p2          = "00"
        header      = CLA.NO_SEC_MSG + INS.GET_CHALLENGE + p1 + p2

        # -------------------------------------------------------- Generate Data
        data        = randDataSize

        apdu        = header + data
        return READER_INTERFACE().sendRawAPDU(apdu)


    # ======================================================================== #
    # RESET RETRY COUNTER                                                      #
    # ======================================================================== #

    def resetRetryCounter(pinID, pin, p1 = "01", retryCounter = "3", maxRetryCounter = "3"):
        byteSize    = 1
        p2 = "04"

        # ------------------------------------------------------ Generate Header
        header      = CLA.NO_SEC_MSG + INS.WRITE_RECORD + p1 + p2

        # -------------------------------------------------------- Generate Data
        data        = pinID + retryCounter + maxRetryCounter + pin
        lc          = SCOSTA.getLength(data, byteSize)

        apdu        = header + lc + data
        return READER_INTERFACE().sendRawAPDU(apdu)


    # ======================================================================== #
    # GET DATA                                                                 #
    # ======================================================================== #

    def getData(fID, p1 = "00", p2 = "41"):
        selectFile(fID)

        # ------------------------------------------------------ Generate Header
        header   = CLA.NO_SEC_MSG + INS.GET_DATA + p1 + p2

        apdu     = header
        return READER_INTERFACE().sendRawAPDU(apdu)


    # ======================================================================== #
    # PUT DATA                                                                 #
    # ======================================================================== #

    def putData(data = "", p1 = "00", p2 = "04"):
        byteSize    = 1

        # ------------------------------------------------------ Generate Header
        header      = CLA.NO_SEC_MSG + INS.PUT_DATA + p1 + p2

        # -------------------------------------------------------- Generate Data
        lc          = SCOSTA.getLength(data, byteSize)

        apdu        = header + lc + data
        return READER_INTERFACE().sendRawAPDU(apdu)


    # ======================================================================== #
    # GET RESPONSE                                                             #
    # ======================================================================== #

    def getResponse(fID, p1 = "00", p2 = "00"):

        # ------------------------------------------------------ Generate Header
        header   = CLA.NO_SEC_MSG + INS.GET_RESPONSE + p1 + p2

        # -------------------------------------------------------- Generate Data
        data     = fID
        lc       = SCOSTA.getLength(data, 1)

        apdu     = header + lc + data
        return READER_INTERFACE().sendRawAPDU(apdu)

    def MSERestore(p2 = '00', p1 = 'F3'):
        """
            Perform MSE Restore
            Mandatory Tag p2 : SEID
        """
        header = CLA.NO_SEC_MSG + INS.MSE + p1 + p2

        apdu = header
        return READER_INTERFACE().sendRawAPDU(apdu)
