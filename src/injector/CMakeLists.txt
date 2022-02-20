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

add_executable(injector
    main.cpp
)

include_directories(
    ${PACKET_SNIFFER_SHARED_HEADERS}
)

target_link_libraries(injector
    shared
    Psapi
    shlwapi
    version
)
