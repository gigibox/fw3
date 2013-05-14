cmake_minimum_required(VERSION 2.6)

PROJECT(firewall3 C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

ADD_EXECUTABLE(firewall3 main.c options.c defaults.c zones.c forwards.c rules.c redirects.c utils.c ubus.c ipsets.c includes.c iptables.c)
TARGET_LINK_LIBRARIES(firewall3 uci ubox ubus ip4tc ip6tc xtables m ${CMAKE_SOURCE_DIR}/libext.a ${CMAKE_SOURCE_DIR}/libext4.a ${CMAKE_SOURCE_DIR}/libext6.a)

SET(CMAKE_INSTALL_PREFIX /usr)

INSTALL(TARGETS firewall3
	RUNTIME DESTINATION sbin
)
