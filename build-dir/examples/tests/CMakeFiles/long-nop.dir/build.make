# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Produce verbose output by default.
VERBOSE = 1

# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/elisa/Desktop/elas_osbi

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/elisa/Desktop/elas_osbi/build-dir

# Include any dependencies generated for this target.
include examples/tests/CMakeFiles/long-nop.dir/depend.make

# Include the progress variables for this target.
include examples/tests/CMakeFiles/long-nop.dir/progress.make

# Include the compile flags for this target's objects.
include examples/tests/CMakeFiles/long-nop.dir/flags.make

examples/tests/add_long.S:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating add_long.S"
	cd /home/elisa/Desktop/elas_osbi/build-dir/examples/tests && ../../../sdk/examples/tests/long-nop/generate_func.sh 4097 /home/elisa/Desktop/elas_osbi/build-dir/examples/tests/add_long.S /home/elisa/Desktop/elas_osbi/sdk/examples/tests/long-nop/nop.s /home/elisa/Desktop/elas_osbi/sdk/examples/tests/long-nop/func_base.s /home/elisa/Desktop/elas_osbi/sdk/examples/tests/long-nop/nop.h

examples/tests/CMakeFiles/long-nop.dir/long-nop/long-nop.S.o: examples/tests/CMakeFiles/long-nop.dir/flags.make
examples/tests/CMakeFiles/long-nop.dir/long-nop/long-nop.S.o: ../sdk/examples/tests/long-nop/long-nop.S
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building ASM object examples/tests/CMakeFiles/long-nop.dir/long-nop/long-nop.S.o"
	cd /home/elisa/Desktop/elas_osbi/build-dir/examples/tests && /home/elisa/Desktop/elas_osbi/riscv64/bin/riscv64-unknown-linux-gnu-gcc $(ASM_DEFINES) $(ASM_INCLUDES) $(ASM_FLAGS) -o CMakeFiles/long-nop.dir/long-nop/long-nop.S.o -c /home/elisa/Desktop/elas_osbi/sdk/examples/tests/long-nop/long-nop.S

examples/tests/CMakeFiles/long-nop.dir/add_long.S.o: examples/tests/CMakeFiles/long-nop.dir/flags.make
examples/tests/CMakeFiles/long-nop.dir/add_long.S.o: examples/tests/add_long.S
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building ASM object examples/tests/CMakeFiles/long-nop.dir/add_long.S.o"
	cd /home/elisa/Desktop/elas_osbi/build-dir/examples/tests && /home/elisa/Desktop/elas_osbi/riscv64/bin/riscv64-unknown-linux-gnu-gcc $(ASM_DEFINES) $(ASM_INCLUDES) $(ASM_FLAGS) -o CMakeFiles/long-nop.dir/add_long.S.o -c /home/elisa/Desktop/elas_osbi/build-dir/examples/tests/add_long.S

# Object files for target long-nop
long__nop_OBJECTS = \
"CMakeFiles/long-nop.dir/long-nop/long-nop.S.o" \
"CMakeFiles/long-nop.dir/add_long.S.o"

# External object files for target long-nop
long__nop_EXTERNAL_OBJECTS =

examples/tests/long-nop: examples/tests/CMakeFiles/long-nop.dir/long-nop/long-nop.S.o
examples/tests/long-nop: examples/tests/CMakeFiles/long-nop.dir/add_long.S.o
examples/tests/long-nop: examples/tests/CMakeFiles/long-nop.dir/build.make
examples/tests/long-nop: ../sdk/build64/lib/libkeystone-eapp.a
examples/tests/long-nop: examples/tests/CMakeFiles/long-nop.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking ASM executable long-nop"
	cd /home/elisa/Desktop/elas_osbi/build-dir/examples/tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/long-nop.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
examples/tests/CMakeFiles/long-nop.dir/build: examples/tests/long-nop

.PHONY : examples/tests/CMakeFiles/long-nop.dir/build

examples/tests/CMakeFiles/long-nop.dir/clean:
	cd /home/elisa/Desktop/elas_osbi/build-dir/examples/tests && $(CMAKE_COMMAND) -P CMakeFiles/long-nop.dir/cmake_clean.cmake
.PHONY : examples/tests/CMakeFiles/long-nop.dir/clean

examples/tests/CMakeFiles/long-nop.dir/depend: examples/tests/add_long.S
	cd /home/elisa/Desktop/elas_osbi/build-dir && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/elisa/Desktop/elas_osbi /home/elisa/Desktop/elas_osbi/sdk/examples/tests /home/elisa/Desktop/elas_osbi/build-dir /home/elisa/Desktop/elas_osbi/build-dir/examples/tests /home/elisa/Desktop/elas_osbi/build-dir/examples/tests/CMakeFiles/long-nop.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : examples/tests/CMakeFiles/long-nop.dir/depend

