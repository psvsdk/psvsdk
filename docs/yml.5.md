	YAML structure example

version: 2
firmware: 3.60
modules:
  SceAppMgr:
    nid: 0xDBB29DB7
    libraries:
    --SceAppMgrForDriver:
    ----kernel: true
    ----nid: 0xDCE180F8
    ----functions:
    ------ksceAppMgrAcInstGetAcdirParam: 0x474AABDF
    ------...
