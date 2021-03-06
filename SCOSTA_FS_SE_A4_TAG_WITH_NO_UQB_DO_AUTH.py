import sys

from HID.SCOSTA_INTERFACE import *

import CAPYTEST_CONFIG
import PY_CAPTEST
import PROPERTIES
import utils


#########################CAPYTEST DESCRIPTIONS #################################

def Properties():
    props = PROPERTIES.TEST_PROPERTIES()
    props.name = "SCOSTA_FS_SE_A4_TAG_WITH_NO_UQB_DO_AUTH"
    props.description = "Try to perform AUTH, when no Usage Qualifier Byte in A4 (Auth. Template) is present."
    props.regression = False
    props.manual = False  # True: automatic, False: Manual


    props.requirements = [
        "SCOSTA_FS_SE_A4_TAG_WITH_NO_UQB_DO_AUTH"
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
    # SCOSTA_FS_SE_A4_TAG_WITH_NO_UQB_DO_AUTH                              #
    # ==================================================================== #

    Status = True
    SW_NO_ERRORS = "9000"

    try:
        # Create Container DF, Create SE File in DF without USAGE QUALIFIER
        # BYTE in A4 Tag, along with Key/PIN Files and select the DF again.
        #
        # Any AUTHENTICATION will pass as default UQB is set to C0 by default.
        # ================================================================ #


        # ================================================================ #
        #  PERSONALIZATION.


        data,sw = READER.sendRawAPDU("00 A4 00 00 02 3F 00")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        # Creating a DF container for SE
        data,sw = READER.sendRawAPDU("00 E0 00 00 10 62 0E 83 02 DF 06 82 01 38 8A 01 05 8D 02 EF03")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        # Create EF for PIN file
        data,sw = READER.sendRawAPDU("00 E0 00 00 13 62 11 83 02 EF01 88 01 08 8A 01 05 82 05 0A 01 00 06 05")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        data,sw = READER.sendRawAPDU("00 D2 01 04 06 81 44 00 01 02 03")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        data,sw = READER.sendRawAPDU("00 A4 00 00 02 EF01")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        data,sw = READER.sendRawAPDU("00 D2 02 04 06 82 44 01 02 03 04")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        data,sw = READER.sendRawAPDU("00 A4 00 00 02 EF01")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        data,sw = READER.sendRawAPDU("00 D2 03 04 06 83 44 02 03 04 05")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        key1="00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"

        # Create EF for KEY file
        data,sw = READER.sendRawAPDU("00 E0 00 00 13 62 11 83 02 EF02 88 01 10 8A 01 05 82 05 0C 01 00 17 05")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        data,sw = READER.sendRawAPDU("00 D2 01 04 14 81 01 55 00 "+key1)
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        # Create EF for SE file
        data,sw = READER.sendRawAPDU("00 E0 00 00 13 62 11 83 02 EF03 88 01 18 8A 01 05 82 05 0C 01 00 20 0A")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        # Control reference template for Authentication template(A4)
        data,sw = READER.sendRawAPDU("00 D2 01 04 08 80 01 01 A4 06 83 01 81")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        data,sw = READER.sendRawAPDU("00 A4 00 00 02 EF03")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        data,sw = READER.sendRawAPDU("00 D2 02 04 08 80 01 02 A4 06 83 01 82")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        data,sw = READER.sendRawAPDU("00 A4 00 00 02 EF03")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        data,sw = READER.sendRawAPDU("00 D2 03 04 08 80 01 03 A4 06 83 01 83")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        data,sw = READER.sendRawAPDU("00 A4 00 00 02 EF03")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        data,sw = READER.sendRawAPDU("00 D2 04 04 08 80 01 04 A4 06 83 01 81")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        # File with pin security- user authentication
        # The last three values 12 13 11 represent pin set for Write, Update
        # and read respectively
        data,sw = READER.sendRawAPDU("00 E0 00 00 16 62 14 82 05 02 01 00 05 0A 83 02 EF 05 8A 01 05 8C 04 07 12 13 11")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        # Create Ef with pin security and Key security, 24 - key security
        # for write, 12 11 are pin security for update, read
        data,sw = READER.sendRawAPDU("00 E0 00 00 16 62 14 82 05 02 01 00 05 0A 83 02 EF 06 8A 01 05 8C 04 07 24 12 11")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


        # ================================================================ #
        #  TEST


        # Get challenge APDU-84 and get random data of given byte
        data,sw = READER.sendRawAPDU("00 84 00 00 08")
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))

        # External authentication 82 using encrypted data
        encData = CRYPTO.DES_Compute_3DES_CBC(data,key1)
        data,sw = READER.sendRawAPDU("00 82 00 81 08" + encData)
        if sw != int(SW_NO_ERRORS, 16):
            raise Exception(SW_NO_ERRORS + " " + str(hex(sw)))


    except Exception as e:
        print("EXPECTED: " + str(e).split(" ")[0])
        print("RECIEVED: " + str(e).split(" ")[1])
        Status = False

    TEST.updateRequirement("SCOSTA_FS_SE_A4_TAG_WITH_NO_UQB_DO_AUTH", Status)

    # ==================================================================== #
    #  CLEANUP


    # Delete the above files created
    READER.sendRawAPDU("00 A4 00 04 02 DF 06")
    READER.sendRawAPDU("00 E4 00 00 02 DF 06")


    TEST.End()
