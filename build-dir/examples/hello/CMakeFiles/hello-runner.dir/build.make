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
include examples/hello/CMakeFiles/hello-runner.dir/depend.make

# Include the progress variables for this target.
include examples/hello/CMakeFiles/hello-runner.dir/progress.make

# Include the compile flags for this target's objects.
include examples/hello/CMakeFiles/hello-runner.dir/flags.make

examples/hello/CMakeFiles/hello-runner.dir/host/host.cpp.o: examples/hello/CMakeFiles/hello-runner.dir/flags.make
examples/hello/CMakeFiles/hello-runner.dir/host/host.cpp.o: ../sdk/examples/hello/host/host.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object examples/hello/CMakeFiles/hello-runner.dir/host/host.cpp.o"
	cd /home/elisa/Desktop/elas_osbi/build-dir/examples/hello && /home/elisa/Desktop/elas_osbi/riscv64/bin/riscv64-unknown-linux-gnu-g++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/hello-runner.dir/host/host.cpp.o -c /home/elisa/Desktop/elas_osbi/sdk/examples/hello/host/host.cpp

examples/hello/CMakeFiles/hello-runner.dir/host/host.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/hello-runner.dir/host/host.cpp.i"
	cd /home/elisa/Desktop/elas_osbi/build-dir/examples/hello && /home/elisa/Desktop/elas_osbi/riscv64/bin/riscv64-unknown-linux-gnu-g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/elisa/Desktop/elas_osbi/sdk/examples/hello/host/host.cpp > CMakeFiles/hello-runner.dir/host/host.cpp.i

examples/hello/CMakeFiles/hello-runner.dir/host/host.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/hello-runner.dir/host/host.cpp.s"
	cd /home/elisa/Desktop/elas_osbi/build-dir/examples/hello && /home/elisa/Desktop/elas_osbi/riscv64/bin/riscv64-unknown-linux-gnu-g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/elisa/Desktop/elas_osbi/sdk/examples/hello/host/host.cpp -o CMakeFiles/hello-runner.dir/host/host.cpp.s

# Object files for target hello-runner
hello__runner_OBJECTS = \
"CMakeFiles/hello-runner.dir/host/host.cpp.o"

# External object files for target hello-runner
hello__runner_EXTERNAL_OBJECTS =

examples/hello/hello-runner: examples/hello/CMakeFiles/hello-runner.dir/host/host.cpp.o
examples/hello/hello-runner: examples/hello/CMakeFiles/hello-runner.dir/build.make
examples/hello/hello-runner: ../sdk/build64/lib/libkeystone-host.a
examples/hello/hello-runner: ../sdk/build64/lib/libkeystone-edge.a
examples/hello/hello-runner: examples/hello/CMakeFiles/hello-runner.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable hello-runner"
	cd /home/elisa/Desktop/elas_osbi/build-dir/examples/hello && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/hello-runner.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
examples/hello/CMakeFiles/hello-runner.dir/build: examples/hello/hello-runner

.PHONY : examples/hello/CMakeFiles/hello-runner.dir/build

examples/hello/CMakeFiles/hello-runner.dir/clean:
	cd /home/elisa/Desktop/elas_osbi/build-dir/examples/hello && $(CMAKE_COMMAND) -P CMakeFiles/hello-runner.dir/cmake_clean.cmake
.PHONY : examples/hello/CMakeFiles/hello-runner.dir/clean

examples/hello/CMakeFiles/hello-runner.dir/depend:
	cd /home/elisa/Desktop/elas_osbi/build-dir && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/elisa/Desktop/elas_osbi /home/elisa/Desktop/elas_osbi/sdk/examples/hello /home/elisa/Desktop/elas_osbi/build-dir /home/elisa/Desktop/elas_osbi/build-dir/examples/hello /home/elisa/Desktop/elas_osbi/build-dir/examples/hello/CMakeFiles/hello-runner.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : examples/hello/CMakeFiles/hello-runner.dir/depend
