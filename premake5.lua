workspace "Compiler"
	configurations { "Debug", "Release" }
	location "proj"
	startproject "testrunner"

	language "C++"
	targetdir "bin/%{cfg.buildcfg}"
	includedirs "src"

	defines "_CRT_SECURE_NO_WARNINGS"

	vpaths {
		["*"] = "src"
	}
	filter "configurations:Debug"
		defines { "DEBUG" }
		flags { "Symbols" }

	filter "configurations:Release"
		defines { "NDEBUG" }
		optimize "On"

	filter "system:windows"
		defines { "OS_WINDOWS" }
	filter "system:linux"
		defines { "OS_LINUX" }


function prelude(name)
	pchheader "prelude.h"
	includedirs("src/"..name.."/prelude")
	pchsource("src/"..name.."/prelude/prelude.cpp")
end

project "os"
	kind "StaticLib"
	files { "src/os/*.h" }

	filter "system:windows"
		prelude "os/win32"
		files { "src/os/win32/**.h", "src/os/win32/**.cpp" }

	filter "system:linux"
		prelude "os/linux"
		files { "src/os/linux/**.h", "src/os/linux/**.cpp" }

project "base"
	kind "StaticLib"
	prelude "base"
	files { "src/base/**.h", "src/base/**.cpp" }

project "test"
	kind "ConsoleApp"
	prelude "test"
	links { "base", "os" }
	files { "src/test/**.h", "src/test/**.cpp" }

project "testrunner"
	kind "ConsoleApp"
	links { "base", "os", "test" }
	files { "src/testrunner/**.h", "src/testrunner/**.cpp" }

