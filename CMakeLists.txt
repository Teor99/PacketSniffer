#   This file is part of PacketSniffer.
#
#   PacketSniffer is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   PacketSniffer is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with PacketSniffer.  If not, see <http://www.gnu.org/licenses/>.

project(PacketSniffer)
cmake_minimum_required(VERSION 2.8.12)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_EXE_LINKER_FLAGS    "${CMAKE_EXE_LINKER_FLAGS} /MANIFEST:NO")
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} /MANIFEST:NO")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /MANIFEST:NO")

add_subdirectory(src)

# project must be compiled in 32-bit mode
# because the targeted WoW process is 32-bit also
# if you compile it with a 64-bit compiler the sniffer won't work
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Only 32-bit compilation allowed!")
endif()
