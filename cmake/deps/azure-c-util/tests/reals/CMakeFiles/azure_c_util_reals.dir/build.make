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
CMAKE_SOURCE_DIR = /mnt/c/azure/azure-c-pal

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /mnt/c/azure/azure-c-pal/cmake

# Include any dependencies generated for this target.
include deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/depend.make

# Include the progress variables for this target.
include deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/progress.make

# Include the compile flags for this target's objects.
include deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/flags.make

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_constbuffer.c.o: deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/flags.make
deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_constbuffer.c.o: ../deps/azure-c-util/tests/reals/real_constbuffer.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/azure/azure-c-pal/cmake/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_constbuffer.c.o"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/azure_c_util_reals.dir/real_constbuffer.c.o   -c /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_constbuffer.c

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_constbuffer.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/azure_c_util_reals.dir/real_constbuffer.c.i"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_constbuffer.c > CMakeFiles/azure_c_util_reals.dir/real_constbuffer.c.i

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_constbuffer.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/azure_c_util_reals.dir/real_constbuffer.c.s"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_constbuffer.c -o CMakeFiles/azure_c_util_reals.dir/real_constbuffer.c.s

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array.c.o: deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/flags.make
deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array.c.o: ../deps/azure-c-util/tests/reals/real_constbuffer_array.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/azure/azure-c-pal/cmake/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array.c.o"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array.c.o   -c /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_constbuffer_array.c

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array.c.i"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_constbuffer_array.c > CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array.c.i

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array.c.s"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_constbuffer_array.c -o CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array.c.s

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array_batcher_nv.c.o: deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/flags.make
deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array_batcher_nv.c.o: ../deps/azure-c-util/tests/reals/real_constbuffer_array_batcher_nv.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/azure/azure-c-pal/cmake/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array_batcher_nv.c.o"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array_batcher_nv.c.o   -c /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_constbuffer_array_batcher_nv.c

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array_batcher_nv.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array_batcher_nv.c.i"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_constbuffer_array_batcher_nv.c > CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array_batcher_nv.c.i

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array_batcher_nv.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array_batcher_nv.c.s"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_constbuffer_array_batcher_nv.c -o CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array_batcher_nv.c.s

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_crt_abstractions.c.o: deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/flags.make
deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_crt_abstractions.c.o: ../deps/azure-c-util/tests/reals/real_crt_abstractions.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/azure/azure-c-pal/cmake/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_crt_abstractions.c.o"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/azure_c_util_reals.dir/real_crt_abstractions.c.o   -c /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_crt_abstractions.c

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_crt_abstractions.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/azure_c_util_reals.dir/real_crt_abstractions.c.i"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_crt_abstractions.c > CMakeFiles/azure_c_util_reals.dir/real_crt_abstractions.c.i

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_crt_abstractions.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/azure_c_util_reals.dir/real_crt_abstractions.c.s"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_crt_abstractions.c -o CMakeFiles/azure_c_util_reals.dir/real_crt_abstractions.c.s

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_doublylinkedlist.c.o: deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/flags.make
deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_doublylinkedlist.c.o: ../deps/azure-c-util/tests/reals/real_doublylinkedlist.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/azure/azure-c-pal/cmake/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_doublylinkedlist.c.o"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/azure_c_util_reals.dir/real_doublylinkedlist.c.o   -c /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_doublylinkedlist.c

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_doublylinkedlist.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/azure_c_util_reals.dir/real_doublylinkedlist.c.i"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_doublylinkedlist.c > CMakeFiles/azure_c_util_reals.dir/real_doublylinkedlist.c.i

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_doublylinkedlist.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/azure_c_util_reals.dir/real_doublylinkedlist.c.s"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_doublylinkedlist.c -o CMakeFiles/azure_c_util_reals.dir/real_doublylinkedlist.c.s

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_memory_data.c.o: deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/flags.make
deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_memory_data.c.o: ../deps/azure-c-util/tests/reals/real_memory_data.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/azure/azure-c-pal/cmake/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_memory_data.c.o"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/azure_c_util_reals.dir/real_memory_data.c.o   -c /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_memory_data.c

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_memory_data.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/azure_c_util_reals.dir/real_memory_data.c.i"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_memory_data.c > CMakeFiles/azure_c_util_reals.dir/real_memory_data.c.i

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_memory_data.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/azure_c_util_reals.dir/real_memory_data.c.s"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_memory_data.c -o CMakeFiles/azure_c_util_reals.dir/real_memory_data.c.s

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_singlylinkedlist.c.o: deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/flags.make
deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_singlylinkedlist.c.o: ../deps/azure-c-util/tests/reals/real_singlylinkedlist.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/azure/azure-c-pal/cmake/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building C object deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_singlylinkedlist.c.o"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/azure_c_util_reals.dir/real_singlylinkedlist.c.o   -c /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_singlylinkedlist.c

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_singlylinkedlist.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/azure_c_util_reals.dir/real_singlylinkedlist.c.i"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_singlylinkedlist.c > CMakeFiles/azure_c_util_reals.dir/real_singlylinkedlist.c.i

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_singlylinkedlist.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/azure_c_util_reals.dir/real_singlylinkedlist.c.s"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_singlylinkedlist.c -o CMakeFiles/azure_c_util_reals.dir/real_singlylinkedlist.c.s

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_threadapi.c.o: deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/flags.make
deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_threadapi.c.o: ../deps/azure-c-util/tests/reals/real_threadapi.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/azure/azure-c-pal/cmake/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building C object deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_threadapi.c.o"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/azure_c_util_reals.dir/real_threadapi.c.o   -c /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_threadapi.c

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_threadapi.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/azure_c_util_reals.dir/real_threadapi.c.i"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_threadapi.c > CMakeFiles/azure_c_util_reals.dir/real_threadapi.c.i

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_threadapi.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/azure_c_util_reals.dir/real_threadapi.c.s"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_threadapi.c -o CMakeFiles/azure_c_util_reals.dir/real_threadapi.c.s

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_uuid.c.o: deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/flags.make
deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_uuid.c.o: ../deps/azure-c-util/tests/reals/real_uuid.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/azure/azure-c-pal/cmake/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building C object deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_uuid.c.o"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/azure_c_util_reals.dir/real_uuid.c.o   -c /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_uuid.c

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_uuid.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/azure_c_util_reals.dir/real_uuid.c.i"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_uuid.c > CMakeFiles/azure_c_util_reals.dir/real_uuid.c.i

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_uuid.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/azure_c_util_reals.dir/real_uuid.c.s"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals/real_uuid.c -o CMakeFiles/azure_c_util_reals.dir/real_uuid.c.s

# Object files for target azure_c_util_reals
azure_c_util_reals_OBJECTS = \
"CMakeFiles/azure_c_util_reals.dir/real_constbuffer.c.o" \
"CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array.c.o" \
"CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array_batcher_nv.c.o" \
"CMakeFiles/azure_c_util_reals.dir/real_crt_abstractions.c.o" \
"CMakeFiles/azure_c_util_reals.dir/real_doublylinkedlist.c.o" \
"CMakeFiles/azure_c_util_reals.dir/real_memory_data.c.o" \
"CMakeFiles/azure_c_util_reals.dir/real_singlylinkedlist.c.o" \
"CMakeFiles/azure_c_util_reals.dir/real_threadapi.c.o" \
"CMakeFiles/azure_c_util_reals.dir/real_uuid.c.o"

# External object files for target azure_c_util_reals
azure_c_util_reals_EXTERNAL_OBJECTS =

deps/azure-c-util/tests/reals/libazure_c_util_reals.a: deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_constbuffer.c.o
deps/azure-c-util/tests/reals/libazure_c_util_reals.a: deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array.c.o
deps/azure-c-util/tests/reals/libazure_c_util_reals.a: deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_constbuffer_array_batcher_nv.c.o
deps/azure-c-util/tests/reals/libazure_c_util_reals.a: deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_crt_abstractions.c.o
deps/azure-c-util/tests/reals/libazure_c_util_reals.a: deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_doublylinkedlist.c.o
deps/azure-c-util/tests/reals/libazure_c_util_reals.a: deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_memory_data.c.o
deps/azure-c-util/tests/reals/libazure_c_util_reals.a: deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_singlylinkedlist.c.o
deps/azure-c-util/tests/reals/libazure_c_util_reals.a: deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_threadapi.c.o
deps/azure-c-util/tests/reals/libazure_c_util_reals.a: deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/real_uuid.c.o
deps/azure-c-util/tests/reals/libazure_c_util_reals.a: deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/build.make
deps/azure-c-util/tests/reals/libazure_c_util_reals.a: deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/mnt/c/azure/azure-c-pal/cmake/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Linking C static library libazure_c_util_reals.a"
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && $(CMAKE_COMMAND) -P CMakeFiles/azure_c_util_reals.dir/cmake_clean_target.cmake
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/azure_c_util_reals.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/build: deps/azure-c-util/tests/reals/libazure_c_util_reals.a

.PHONY : deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/build

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/clean:
	cd /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals && $(CMAKE_COMMAND) -P CMakeFiles/azure_c_util_reals.dir/cmake_clean.cmake
.PHONY : deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/clean

deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/depend:
	cd /mnt/c/azure/azure-c-pal/cmake && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /mnt/c/azure/azure-c-pal /mnt/c/azure/azure-c-pal/deps/azure-c-util/tests/reals /mnt/c/azure/azure-c-pal/cmake /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals /mnt/c/azure/azure-c-pal/cmake/deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : deps/azure-c-util/tests/reals/CMakeFiles/azure_c_util_reals.dir/depend
