cmake_minimum_required(VERSION 3.20)

project(DigitalVault LANGUAGES NONE)

find_package(Java 17 REQUIRED COMPONENTS Runtime Development)

set(BOUNCY_CASTLE_JAR
    "${CMAKE_SOURCE_DIR}/lib/bcprov-jdk18on-1.80.2.jar")
set(SQLITE_JDBC_JAR
    "${CMAKE_SOURCE_DIR}/lib/sqlite-jdbc-3.41.2.2.jar")
set(ZXING_CORE_JAR
    "${CMAKE_SOURCE_DIR}/lib/core-3.5.4.jar")

if(NOT EXISTS "${BOUNCY_CASTLE_JAR}")
    message(FATAL_ERROR "BouncyCastle JAR not found: ${BOUNCY_CASTLE_JAR}")
endif()

if(NOT EXISTS "${SQLITE_JDBC_JAR}")
    message(FATAL_ERROR "SQLite JDBC JAR not found: ${SQLITE_JDBC_JAR}")
endif()

if(NOT EXISTS "${ZXING_CORE_JAR}")
    message(FATAL_ERROR "ZXing Core JAR not found: ${ZXING_CORE_JAR}")
endif()

if(WIN32)
    set(CLASSPATH_SEPARATOR ";")
else()
    set(CLASSPATH_SEPARATOR ":")
endif()

set(DEPENDENCY_CLASSPATH
    "${BOUNCY_CASTLE_JAR}${CLASSPATH_SEPARATOR}${SQLITE_JDBC_JAR}${CLASSPATH_SEPARATOR}${ZXING_CORE_JAR}")
set(CLASS_DIRECTORY "${CMAKE_BINARY_DIR}/classes")
set(RUNTIME_CLASSPATH
    "${CLASS_DIRECTORY}${CLASSPATH_SEPARATOR}${DEPENDENCY_CLASSPATH}")

file(GLOB APPLICATION_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/src/*.java")
set(TEST_SOURCE "${CMAKE_SOURCE_DIR}/tests/Tests.java")
set(COMPILE_STAMP "${CMAKE_BINARY_DIR}/java-compile.stamp")

add_custom_command(
    OUTPUT "${COMPILE_STAMP}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${CLASS_DIRECTORY}"
    COMMAND "${Java_JAVAC_EXECUTABLE}"
            -Xlint:all
            -encoding UTF-8
            -cp "${DEPENDENCY_CLASSPATH}"
            -d "${CLASS_DIRECTORY}"
            ${APPLICATION_SOURCES}
            "${TEST_SOURCE}"
    COMMAND "${CMAKE_COMMAND}" -E touch "${COMPILE_STAMP}"
    DEPENDS
            ${APPLICATION_SOURCES}
            "${TEST_SOURCE}"
            "${BOUNCY_CASTLE_JAR}"
            "${SQLITE_JDBC_JAR}"
            "${ZXING_CORE_JAR}"
    COMMENT "Compiling Digital Vault Java sources"
    VERBATIM
)

add_custom_target(compile_java ALL DEPENDS "${COMPILE_STAMP}")

add_custom_target(run
    COMMAND "${Java_JAVA_EXECUTABLE}"
            --enable-native-access=ALL-UNNAMED
            -cp "${RUNTIME_CLASSPATH}"
            DigitalVault
    DEPENDS compile_java
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    USES_TERMINAL
)

add_custom_target(run_tests
    COMMAND "${Java_JAVA_EXECUTABLE}"
            --enable-native-access=ALL-UNNAMED
            -cp "${RUNTIME_CLASSPATH}"
            Tests
    DEPENDS compile_java
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    USES_TERMINAL
)

add_custom_target(run_package_tests
    COMMAND "${Java_JAVA_EXECUTABLE}"
            --enable-native-access=ALL-UNNAMED
            -cp "${RUNTIME_CLASSPATH}"
            Tests --package-t3
    DEPENDS compile_java
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    USES_TERMINAL
)
