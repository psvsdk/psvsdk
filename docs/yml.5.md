# Vita NID DB YAML structure

    version: 2
    firmware: 3.60
    modules:
      SceAppMgr:
        nid: 0xDBB29DB7
        libraries:
          SceAppMgrForDriver:
            kernel: true
            nid: 0xDCE180F8
            functions:
              ksceAppMgrAcInstGetAcdirParam: 0x474AABDF
              ...

# Vita ELF Export YAML structure

    MyModule:
      attributes: 0
      version:
        major: 1
        minor: 0
      main:
        start: module_start
      libraries:
        MyLib:
          syscall: false
          functions:
            - ml_funcA
