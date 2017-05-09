cmake_minimum_required(VERSION 2.6)

PROJECT(firewall3 C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations -Wno-format-truncation)

SET(iptc_libs   ip4tc)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF (NOT DISABLE_STATIC_EXTENSIONS)
  LIST(APPEND ext_libs iptext)
  LIST(APPEND ext_libs iptext4)
  IF (NOT DISABLE_IPV6)
    LIST(APPEND ext_libs iptext6)
  ENDIF()
ELSE()
  ADD_DEFINITIONS(-DDISABLE_STATIC_EXTENSIONS)
ENDIF()

IF (NOT DISABLE_IPV6)
  LIST(APPEND iptc_libs ip6tc)
ELSE()
  ADD_DEFINITIONS(-DDISABLE_IPV6)
ENDIF()

FIND_PATH(uci_include_dir uci.h)
INCLUDE_DIRECTORIES(${uci_include_dir})

ADD_EXECUTABLE(firewall3 main.c options.c defaults.c zones.c forwards.c rules.c redirects.c snats.c utils.c ubus.c ipsets.c includes.c iptables.c)
TARGET_LINK_LIBRARIES(firewall3 uci ubox ubus xtables m dl ${iptc_libs} ${ext_libs})

SET(CMAKE_INSTALL_PREFIX /usr)

INSTALL(TARGETS firewall3 RUNTIME DESTINATION sbin)
