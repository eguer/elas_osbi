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

# Utility rule file for driver.

# Include the progress variables for this target.
include CMakeFiles/driver.dir/progress.make

CMakeFiles/driver: ../linux-keystone-driver
CMakeFiles/driver: ../linux
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building driver"
	$(MAKE) -C /home/elisa/Desktop/elas_osbi/build-dir/linux.build O=/home/elisa/Desktop/elas_osbi/build-dir/linux.build CROSS_COMPILE=riscv64-unknown-linux-gnu- ARCH=riscv M=/home/elisa/Desktop/elas_osbi/build-dir/linux-keystone-driver.build modules

driver: CMakeFiles/driver
driver: CMakeFiles/driver.dir/build.make

.PHONY : driver

# Rule to build all files generated by this target.
CMakeFiles/driver.dir/build: driver

.PHONY : CMakeFiles/driver.dir/build

CMakeFiles/driver.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/driver.dir/cmake_clean.cmake
.PHONY : CMakeFiles/driver.dir/clean

CMakeFiles/driver.dir/depend:
	cd /home/elisa/Desktop/elas_osbi/build-dir && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/elisa/Desktop/elas_osbi /home/elisa/Desktop/elas_osbi /home/elisa/Desktop/elas_osbi/build-dir /home/elisa/Desktop/elas_osbi/build-dir /home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles/driver.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/driver.dir/depend

