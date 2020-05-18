set(SOURCES
	Main.cpp
)

add_executable(LyketoCLI ${SOURCES})
target_link_libraries(LyketoCLI LibLyketo)
