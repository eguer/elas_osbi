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

# Utility rule file for hello-native-package.

# Include the progress variables for this target.
include examples/hello-native/CMakeFiles/hello-native-package.dir/progress.make

examples/hello-native/CMakeFiles/hello-native-package: examples/hello-native/pkg/.options_log
examples/hello-native/CMakeFiles/hello-native-package: examples/hello-native/pkg/eyrie-rt
examples/hello-native/CMakeFiles/hello-native-package: examples/hello-native/pkg/hello-native
examples/hello-native/CMakeFiles/hello-native-package: examples/hello-native/pkg/hello-native-runner
	cd /home/elisa/Desktop/elas_osbi/build-dir/examples/hello-native && /usr/bin/makeself --noprogress /home/elisa/Desktop/elas_osbi/build-dir/examples/hello-native/pkg hello-native.ke "Keystone Enclave Package" ./hello-native-runner hello-native eyrie-rt

examples/hello-native/pkg/.options_log: examples/hello-native/.options_log
examples/hello-native/pkg/.options_log: examples/hello-native/pkg
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating pkg/.options_log"
	cd /home/elisa/Desktop/elas_osbi/build-dir/examples/hello-native && cp .options_log /home/elisa/Desktop/elas_osbi/build-dir/examples/hello-native/pkg/.options_log

examples/hello-native/pkg/eyrie-rt: examples/hello-native/eyrie-rt
examples/hello-native/pkg/eyrie-rt: examples/hello-native/pkg
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Generating pkg/eyrie-rt"
	cd /home/elisa/Desktop/elas_osbi/build-dir/examples/hello-native && cp eyrie-rt /home/elisa/Desktop/elas_osbi/build-dir/examples/hello-native/pkg/eyrie-rt

examples/hello-native/pkg/hello-native: examples/hello-native/hello-native
examples/hello-native/pkg/hello-native: examples/hello-native/pkg
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Generating pkg/hello-native"
	cd /home/elisa/Desktop/elas_osbi/build-dir/examples/hello-native && cp hello-native /home/elisa/Desktop/elas_osbi/build-dir/examples/hello-native/pkg/hello-native

examples/hello-native/pkg/hello-native-runner: examples/hello-native/hello-native-runner
examples/hello-native/pkg/hello-native-runner: examples/hello-native/pkg
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Generating pkg/hello-native-runner"
	cd /home/elisa/Desktop/elas_osbi/build-dir/examples/hello-native && cp hello-native-runner /home/elisa/Desktop/elas_osbi/build-dir/examples/hello-native/pkg/hello-native-runner

examples/hello-native/.options_log: examples/hello-native/runtime/src/eyrie-hello-native-eyrie/.options_log
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Generating .options_log"
	cd /home/elisa/Desktop/elas_osbi/build-dir/examples/hello-native && cp /home/elisa/Desktop/elas_osbi/build-dir/examples/hello-native/runtime/src/eyrie-hello-native-eyrie/.options_log .options_log

examples/hello-native/pkg:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Generating pkg"
	cd /home/elisa/Desktop/elas_osbi/build-dir/examples/hello-native && mkdir /home/elisa/Desktop/elas_osbi/build-dir/examples/hello-native/pkg

examples/hello-native/eyrie-rt: examples/hello-native/runtime/src/eyrie-hello-native-eyrie/eyrie-rt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/elisa/Desktop/elas_osbi/build-dir/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Generating eyrie-rt"
	cd /home/elisa/Desktop/elas_osbi/build-dir/examples/hello-native && cp /home/elisa/Desktop/elas_osbi/build-dir/examples/hello-native/runtime/src/eyrie-hello-native-eyrie/eyrie-rt eyrie-rt

hello-native-package: examples/hello-native/CMakeFiles/hello-native-package
hello-native-package: examples/hello-native/pkg/.options_log
hello-native-package: examples/hello-native/pkg/eyrie-rt
hello-native-package: examples/hello-native/pkg/hello-native
hello-native-package: examples/hello-native/pkg/hello-native-runner
hello-native-package: examples/hello-native/.options_log
hello-native-package: examples/hello-native/pkg
hello-native-package: examples/hello-native/eyrie-rt
hello-native-package: examples/hello-native/CMakeFiles/hello-native-package.dir/build.make

.PHONY : hello-native-package

# Rule to build all files generated by this target.
examples/hello-native/CMakeFiles/hello-native-package.dir/build: hello-native-package

.PHONY : examples/hello-native/CMakeFiles/hello-native-package.dir/build

examples/hello-native/CMakeFiles/hello-native-package.dir/clean:
	cd /home/elisa/Desktop/elas_osbi/build-dir/examples/hello-native && $(CMAKE_COMMAND) -P CMakeFiles/hello-native-package.dir/cmake_clean.cmake
.PHONY : examples/hello-native/CMakeFiles/hello-native-package.dir/clean

examples/hello-native/CMakeFiles/hello-native-package.dir/depend:
	cd /home/elisa/Desktop/elas_osbi/build-dir && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/elisa/Desktop/elas_osbi /home/elisa/Desktop/elas_osbi/sdk/examples/hello-native /home/elisa/Desktop/elas_osbi/build-dir /home/elisa/Desktop/elas_osbi/build-dir/examples/hello-native /home/elisa/Desktop/elas_osbi/build-dir/examples/hello-native/CMakeFiles/hello-native-package.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : examples/hello-native/CMakeFiles/hello-native-package.dir/depend
