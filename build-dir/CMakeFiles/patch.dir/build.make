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

# Utility rule file for patch.

# Include the progress variables for this target.
include CMakeFiles/patch.dir/progress.make

CMakeFiles/patch: qemu-secure-boot.patch.applied
CMakeFiles/patch: linux64.patch.applied
CMakeFiles/patch: opensbi-firmware-secure-boot.patch.applied


qemu-secure-boot.patch.applied:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Applying qemu-secure-boot.patch"
	cd /home/elisa/Desktop/elas_osbi/qemu && patch --forward -p0 < /home/elisa/Desktop/elas_osbi/patches/qemu/qemu-secure-boot.patch || true
	cd /home/elisa/Desktop/elas_osbi/qemu && touch /home/elisa/Desktop/elas_osbi/build-dir/qemu-secure-boot.patch.applied

linux64.patch.applied:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Applying linux64.patch"
	cd /home/elisa/Desktop/elas_osbi/linux && patch --forward -p0 < /home/elisa/Desktop/elas_osbi/patches/linux/linux64.patch || true
	cd /home/elisa/Desktop/elas_osbi/linux && touch /home/elisa/Desktop/elas_osbi/build-dir/linux64.patch.applied

opensbi-firmware-secure-boot.patch.applied:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Applying opensbi-firmware-secure-boot.patch"
	cd /home/elisa/Desktop/elas_osbi/sm/opensbi && patch --forward -p0 < /home/elisa/Desktop/elas_osbi/patches/sm/opensbi/opensbi-firmware-secure-boot.patch || true
	cd /home/elisa/Desktop/elas_osbi/sm/opensbi && touch /home/elisa/Desktop/elas_osbi/build-dir/opensbi-firmware-secure-boot.patch.applied

patch: CMakeFiles/patch
patch: qemu-secure-boot.patch.applied
patch: linux64.patch.applied
patch: opensbi-firmware-secure-boot.patch.applied
patch: CMakeFiles/patch.dir/build.make

.PHONY : patch

# Rule to build all files generated by this target.
CMakeFiles/patch.dir/build: patch

.PHONY : CMakeFiles/patch.dir/build

CMakeFiles/patch.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/patch.dir/cmake_clean.cmake
.PHONY : CMakeFiles/patch.dir/clean

CMakeFiles/patch.dir/depend:
	cd /home/elisa/Desktop/elas_osbi/build-dir && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/elisa/Desktop/elas_osbi /home/elisa/Desktop/elas_osbi /home/elisa/Desktop/elas_osbi/build-dir /home/elisa/Desktop/elas_osbi/build-dir /home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles/patch.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/patch.dir/depend
