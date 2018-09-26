import sys

from HID.SCOSTA_INTERFACE import *

import CAPYTEST_CONFIG
import PY_CAPTEST
import PROPERTIES
import utils


#########################CAPYTEST DESCRIPTIONS #################################

def Properties():
    props = PROPERTIES.TEST_PROPERTIES()
    props.name = "SCOSTA_FS_INT_AUTH_ALGO_NOT_SUPPORTED"
    props.description = "Try to perform AUTH when given ALGO is not supported."
    props.regression = False
    props.manual = False  # True: automatic, False: Manual


    props.requirements = [
        "SCOSTA_FS_INT_AUTH_ALGO_NOT_SUPPORTED"
    ]


    props.type = "nominal"  # nominal / error
    props.interface = ""  # CT / CL / Dual
    props.profile = ""
    props.material = ""  # Emulator / Flash / Card
    props.initialstate = ""
    props.finalstate = ""
    props.campain = "TEST CAMPAIN"
    return props


############################### INIT SOURCE CODE ###############################

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


    # ==================================================================== #
    # SCOSTA_FS_INT_AUTH_ALGO_NOT_SUPPORTED                                #
    # ==================================================================== #

    Status = True
    SW_NO_ERRORS = "9000"
    SW_INCORRECT_P1P2 = "6a86"
    SW_COND_NOT_SATISFIED = "6985"

    try:
        # Create Container DF, Create SE File in DF with WRONG ALGO, along with Key/PIN Files.
        # At this time and select DF.
        #
        # Any AUTHENTICATION will fail.
        # ================================================================ #


        data,sw = READER.sendRawAPDU("00 A4 00 00 02 3F 00")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        data,sw = READER.sendRawAPDU("00 E0 00 00 10 62 0E 83 02 DF 06 82 01 38 8A 01 01 8D 02 EF03")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        key1 = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
        key2 = "01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10"
        key3 = "02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11"

        # Create EF for KEY file
        data,sw = READER.sendRawAPDU("00 E0 00 00 13 62 11 83 02 EF02 88 01 10 8A 01 01 82 05 0C 01 00 17 05")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        data,sw = READER.sendRawAPDU("00 D2 01 04 16 81 03 01 00 55 00 " + key1)
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        # Create EF for SE file
        data,sw = READER.sendRawAPDU("00 E0 00 00 13 62 11 83 02 EF03 88 01 18 8A 01 01 82 05 0C 01 00 20 0A")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        # Control reference template for Authentication template(A4)
        data,sw = READER.sendRawAPDU("00 D2 01 04 0B 80 01 01 A4 06 83 01 81 95 01 C0")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        # Create Ef with pin security and Key security, 24 - key security
        # for write, 12 11 are pin security for update, read
        data,sw = READER.sendRawAPDU("00 E0 00 00 16 62 14 82 05 02 01 00 05 0A 83 02 EF 06 8A 01 01 8C 04 07 21 21 21")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        # Test Internal authentication
        plainText = "1122334455667788"
        encdata,sw = READER.sendRawAPDU("00 88 0F 81 08" + plainText)
        if sw != int(SW_INCORRECT_P1P2, 16):
            raise Exception(SW_INCORRECT_P1P2 + " " + str(hex(sw)))

        data = CRYPTO.DES_Compute_3DES_CBC(encdata, key1, cipher=False)

        if (plainText == data):
            raise Exception(SW_NO_ERRORS + " " + SW_COND_NOT_SATISFIED)

    except Exception as e:
        print("EXPECTED: " + str(e).split(" ")[0])
        print("RECIEVED: " + str(e).split(" ")[1])
        Status = False

    TEST.updateRequirement("SCOSTA_FS_INT_AUTH_ALGO_NOT_SUPPORTED", Status)

    # ==================================================================== #
    #  CLEANUP


    #Delete the above files created
    READER.sendRawAPDU("00 A4 00 00 02 DF 06")
    READER.sendRawAPDU("00 44 00 00 02 DF 06")
    READER.sendRawAPDU("00 E4 00 00 02 DF 06")



    TEST.End()
