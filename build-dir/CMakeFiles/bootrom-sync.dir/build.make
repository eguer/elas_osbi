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

# Utility rule file for bootrom-sync.

# Include the progress variables for this target.
include CMakeFiles/bootrom-sync.dir/progress.make

CMakeFiles/bootrom-sync: ../bootrom
CMakeFiles/bootrom-sync: bootrom.build
	rsync -r /home/elisa/Desktop/elas_osbi/bootrom/ /home/elisa/Desktop/elas_osbi/build-dir/bootrom.build

bootrom.build:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating bootrom.build"
	mkdir -p /home/elisa/Desktop/elas_osbi/build-dir/bootrom.build

bootrom-sync: CMakeFiles/bootrom-sync
bootrom-sync: bootrom.build
bootrom-sync: CMakeFiles/bootrom-sync.dir/build.make

.PHONY : bootrom-sync

# Rule to build all files generated by this target.
CMakeFiles/bootrom-sync.dir/build: bootrom-sync

.PHONY : CMakeFiles/bootrom-sync.dir/build

CMakeFiles/bootrom-sync.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/bootrom-sync.dir/cmake_clean.cmake
.PHONY : CMakeFiles/bootrom-sync.dir/clean

CMakeFiles/bootrom-sync.dir/depend:
	cd /home/elisa/Desktop/elas_osbi/build-dir && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/elisa/Desktop/elas_osbi /home/elisa/Desktop/elas_osbi /home/elisa/Desktop/elas_osbi/build-dir /home/elisa/Desktop/elas_osbi/build-dir /home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles/bootrom-sync.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/bootrom-sync.dir/depend

