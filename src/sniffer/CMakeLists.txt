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

add_library(sniffer SHARED
    main.cpp
    ConsoleManager.h
    HookManager.h
    PacketDump.h
)

target_link_libraries(sniffer
    shared
    Psapi
    shlwapi
    version
    Ws2_32
)

include_directories(
    ${PACKET_SNIFFER_SHARED_HEADERS}
)

# this condition is unnecessary but...
if(WIN32)
    # copies the README and COPYING files to the output directory (build/bin)
    add_custom_command(TARGET sniffer POST_BUILD COMMAND
                       ${CMAKE_COMMAND} -E copy
                       ${PROJECT_SOURCE_DIR}/README.md
                       ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

    add_custom_command(TARGET sniffer POST_BUILD COMMAND
                       ${CMAKE_COMMAND} -E copy
                       ${PROJECT_SOURCE_DIR}/COPYING
                       ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

    add_custom_command(TARGET sniffer POST_BUILD COMMAND
                       ${CMAKE_COMMAND} -E copy
                       ${PROJECT_SOURCE_DIR}/config.ini
                       ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

    add_custom_command(TARGET sniffer POST_BUILD COMMAND
                       ${CMAKE_COMMAND} -E copy
                       ${PROJECT_SOURCE_DIR}/launch.bat
                       ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
endif()
