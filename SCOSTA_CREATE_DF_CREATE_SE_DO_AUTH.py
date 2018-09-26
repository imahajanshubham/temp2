import sys
import CAPYTEST_CONFIG
import PY_CAPTEST
import PROPERTIES
import utils
from HID.SCOSTA_INTERFACE import *


#########################CAPYTEST DESCRIPTIONS #################################
def Properties():
    props = PROPERTIES.TEST_PROPERTIES()
    props.name = "SCOSTA_MSE_7B_Tag"
    props.description = "Perform MSE Restore when CRT template is present in FCP of DF"
    props.regression = False
    props.manual = False  # True: automatic, False: Manual
    props.requirements = ['SCOSTA_MSE_7B_Tag']  # ["TEST_REQ1","TEST_REQ2"]
    props.type = "nominal"  # nominal / error
    props.interface = ""  # CT / CL / Dual
    props.profile = ""
    props.material = ""  # Emulator / Flash / Card
    props.initialstate = ""
    props.finalstate = ""
    props.campain = "TEST CAMPAIN"
    return props


if __name__ == "__main__":
    TEST = PY_CAPTEST.CAPYTEST(Properties())
    instances = TEST.Start()


    # add or remove modules declarations from this list, depending on your needs
    READER = instances["READER"]
    LOGGER = instances["LOGGER"]
    CRYPTO = instances["CRYPTO"]
    #end of list


    if len(sys.argv) > 1:  # reader passed in parameter ? use it
        READER.setCurrentReaderByName(sys.argv[1])
    else:
        READER.setCurrentReaderByName("Identiv uTrust 4700 F Contact Reader 0")


    READER.powerON()


    Status = True
    SW_NO_ERRORS = 0x9000
    SW_REF_DATA_NOT_FOUND = 0x6a88


    try :
        data, sw = SCOSTA.selectFile(fID = "3F00")
        if sw != SW_NO_ERRORS:
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        data, sw = SCOSTA.createDF(fID = "DF03", seID = "EF 03")

        if sw != SW_NO_ERRORS:
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        data, sw = SCOSTA.createRecordFile(fID = "EF01", fdb = "0A", recordLen = "00 06", noOfRecords = "05")

        if sw != SW_NO_ERRORS:
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        data, sw = SCOSTA.writeRecord(p1 = "01", recordData = "81 44 00 01 02 03")

        if sw != SW_NO_ERRORS:
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        data, sw = SCOSTA.selectFile(fID = "EF01")

        if sw != SW_NO_ERRORS:
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        data, sw = SCOSTA.writeRecord(p1 = "02", recordData = "82 44 01 02 03 04")

        if sw != SW_NO_ERRORS:
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        data, sw = SCOSTA.writeRecord(p1 = "03", recordData = "83 44 02 03 04 05")

        if sw != SW_NO_ERRORS:
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        key1 = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"


        # Create EF for KEY file

        data, sw = SCOSTA.createRecordFile(fID = "EF02", fdb = "0A", recordLen = "00 17", noOfRecords = "05")

        if sw != SW_NO_ERRORS:
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        data, sw = SCOSTA.selectFile(fID = "EF02")
        if sw != SW_NO_ERRORS:
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        # ta,sw = READER.sendRawAPDU("00 D2 01 04 14 81 01 55 00 "+key1)
        data, sw = SCOSTA.writeRecord(p1 = "01", recordData = "81 01 55 00" + key1)

        if sw != SW_NO_ERRORS:
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        # Create EF for SE file
        data, sw = SCOSTA.createRecordFile(fID = "EF03", fdb = "0A", recordLen = "00 20", noOfRecords = "0A")

        if sw != SW_NO_ERRORS:
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        # Control reference template for Authentication template(A4)
        data, sw = SCOSTA.writeRecord(p1 = "01", recordData = "80 01 01 A4 06 83 01 81")

        if sw != SW_NO_ERRORS:
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        data, sw = SCOSTA.selectFile("EF03")

        if sw != SW_NO_ERRORS:
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        data, sw = SCOSTA.writeRecord(p1 = "02", recordData = "80 01 02 A4 06 83 01 82")

        if sw != SW_NO_ERRORS:
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        data, sw = SCOSTA.selectFile("EF03")

        if sw != SW_NO_ERRORS:
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        data, sw = SCOSTA.writeRecord(p1 = "03", recordData = "80 01 03 A4 06 83 01 83")

        if sw != SW_NO_ERRORS:
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        data, sw = SCOSTA.selectFile("EF03")

        if sw != SW_NO_ERRORS:
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        data, sw = SCOSTA.writeRecord(p1 = "04", recordData = "80 01 04 A4 06 83 01 81")

        if sw != SW_NO_ERRORS:
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        # File with pin security- user authentication
        # The last three values 12 13 11 represent pin set for Write,
        # Update and read respectively

        data, sw = SCOSTA.createRecordFile(fID = "EF05", fdb = "0A", recordLen = "00 05", noOfRecords = "0A", accessModeByte = "07 12 13 11")

        if sw != SW_NO_ERRORS:
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        # ==================================================================== #
        #  TEST


        # Get challenge APDU-84 and get random data of given byte

        data, sw = SCOSTA.getChallenge("08")
        if sw != SW_NO_ERRORS:
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        # External authentication 82 using encrypted data
        encData = CRYPTO.DES_Compute_3DES_CBC(data, key1)
        data,sw = READER.sendRawAPDU("00 82 00 81 08" + encData)


        # SE shouldn't be set by Default.
        if sw != SW_NO_ERRORS:
##        if sw != int(SW_REF_DATA_NOT_FOUND, 16):
            raise Exception(SW_REF_DATA_NOT_FOUND + " " + str(hex(sw)))


    except Exception as e:
        print("EXPECTED: " + str(e).split(" ")[0])
        print("RECIEVED: " + str(e).split(" ")[1])
        Status = False

    TEST.updateRequirement("SCOSTA_MSE_7B_Tag", Status)

    # ==================================================================== #
    #  CLEANUP


    SCOSTA.selectFile("3F00")
    SCOSTA.deleteFile("DF03")


    TEST.End()
################################################################################