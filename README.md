## Copyright (C) 2012 Łukasz Czerwiński
  
## StructCompacter
StructCompacter reads object (\*.o) file in ELF format and using DWARF debug info section detects structs and theirs members, calculates padding and tries such shuffle with members to minimalize padding space and save memory.
  
## Website
https://github.com/wo3kie/structCompacter

## Requirements
pyelftool library (https://bitbucket.org/eliben/pyelftools)
  
## How to run it?
```
>python bin\sc.py priv\library.o
Reading DWARF (may take some time)...
Fixing types...
Finding paddings...
Compacting structs...
... and finally:
Files Mutex.old.64.sc Mutex.new.56.sc created
Done.
  
>vim -d Mutex.old.64.sc Mutex.new.56.sc
__inheritance  (+0)[d{LockableBase} (8:8)]  |  __inheritance  (+0)[d{LockableBase} (8:8)]
_attr          (+8)[u{._10} (4:4)]          |  _attr          (+8)[u{._10} (4:4)]
              (+12)[char[4] (4:1)]          |  _status       (+12)[int (4:4)]
_mutex        (+16)[u{._9} (40:8)]          |  _mutex        (+16)[u{._9} (40:8)]
_status       (+56)[int (4:4)]              |  ~
              (+60)[char[4] (4:1)]          |  ~
```

