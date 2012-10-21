cmake_minimum_required(VERSION 2.6)
project (pstack)
add_executable(pstack dead.cc dump.cc dwarf.cc elf.cc live.cc process.cc proc_service.cc pstack.cc reader.cc )

if(NOT ELF_BITS)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  SET(ELF_BITS 64)  
endif(CMAKE_SIZEOF_VOID_P EQUAL 8)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
  SET(ELF_BITS 32)  
endif(CMAKE_SIZEOF_VOID_P EQUAL 4)
endif(NOT ELF_BITS)

if(CMAKE_COMPILER_IS_GNUCXX)
    add_definitions("-std=c++0x")
endif(CMAKE_COMPILER_IS_GNUCXX)

add_definitions("-DELF_BITS=${ELF_BITS}")

if("${CMAKE_SYSTEM}" MATCHES "Linux")
    target_link_libraries(pstack "-lthread_db")
endif("${CMAKE_SYSTEM}" MATCHES "Linux")