cmake_minimum_required(VERSION 2.6)

PROJECT(firewall3 C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations)

SET(iptc_libs   ip4tc)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

LIST(APPEND ext_libs iptext)
LIST(APPEND ext_libs iptext4)

IF (NOT DISABLE_IPV6)
  LIST(APPEND ext_libs iptext6)
  LIST(APPEND iptc_libs ip6tc)
ELSE()
  ADD_DEFINITIONS(-DDISABLE_IPV6)
ENDIF()

ADD_EXECUTABLE(firewall3 main.c options.c defaults.c zones.c forwards.c rules.c redirects.c snats.c utils.c ubus.c ipsets.c includes.c iptables.c)
TARGET_LINK_LIBRARIES(firewall3 uci ubox ubus xtables m dl ${iptc_libs} ${ext_libs})

SET(CMAKE_INSTALL_PREFIX /usr)

INSTALL(TARGETS firewall3 RUNTIME DESTINATION sbin)
