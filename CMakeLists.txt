cmake_minimum_required(VERSION 2.6)

PROJECT(firewall3 C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations)

SET(iptc_libs   ip4tc)

SET(sed_match   "^[[:space:]]*__ipt_module(\\(.*\\)).*")
SET(sed_replace "-Wl,--undefined=libxt_\\1_init -Wl,--undefined=libipt_\\1_init -Wl,--undefined=libip6t_\\1_init")

EXECUTE_PROCESS(COMMAND sed -n -e "s/${sed_match}/${sed_replace}/; T n; H; :n; \${ x; s/^\\n//; s/\\n/ /gp }" ${CMAKE_SOURCE_DIR}/iptables.h
                OUTPUT_VARIABLE ext_syms OUTPUT_STRIP_TRAILING_WHITESPACE)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--unresolved-symbols=ignore-all ${ext_syms}")

IF (EXISTS "${CMAKE_SOURCE_DIR}/libext.a")
  ADD_LIBRARY(ext STATIC IMPORTED)
  SET_PROPERTY(TARGET ext PROPERTY IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/libext.a)
  LIST(APPEND ext_libs ext)
ENDIF()

IF (EXISTS "${CMAKE_SOURCE_DIR}/libext4.a")
  ADD_LIBRARY(ext4 STATIC IMPORTED)
  SET_PROPERTY(TARGET ext4 PROPERTY IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/libext4.a")
  LIST(APPEND ext_libs ext4)
ENDIF()

IF (NOT DISABLE_IPV6)
  IF (EXISTS "${CMAKE_SOURCE_DIR}/libext6.a")
	ADD_LIBRARY(ext6 STATIC IMPORTED)
	SET_PROPERTY(TARGET ext6 PROPERTY IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/libext6.a")
	LIST(APPEND ext_libs ext6)
  ENDIF()
  LIST(APPEND iptc_libs ip6tc)
ELSE()
  ADD_DEFINITIONS(-DDISABLE_IPV6)
ENDIF()

ADD_EXECUTABLE(firewall3 main.c options.c defaults.c zones.c forwards.c rules.c redirects.c utils.c ubus.c ipsets.c includes.c iptables.c)
TARGET_LINK_LIBRARIES(firewall3 uci ubox ubus xtables m dl ${iptc_libs} ${ext_libs})

SET(CMAKE_INSTALL_PREFIX /usr)

INSTALL(TARGETS firewall3 RUNTIME DESTINATION sbin)
