workspace "Vault"
   architecture "x64"
   startproject "Vault"

   configurations
   {
      "VAULT_DEBUG",
      "VAULT_RELEASE",
      "VAULT_DIST"
   }

   flags
   {
      "MultiProcessorCompile"
   }

outputdir = "%{cfg.buildcfg}-%{cfg.system}-%{cfg.architecture}"

project "Vault"
   location "Vault"
   kind "ConsoleApp"
   language "C++"
   cppdialect "C++20"
   staticruntime "on"

   targetdir ("$(SolutionDir)Binaries/" .. outputdir .. "/%{prj.name}")
   objdir ("$(SolutionDir)Intermediates/" .. outputdir .. "/%{prj.name}")

   files
   {
      "%{prj.name}/src/**.h",
      "%{prj.name}/src/**.cpp"
   }

   defines
   {
      "VAULT_PLATFORM_WINDOWS",
      "UNICODE",
      "_UNICODE"
   }

   includedirs
   {
      -- Add bcrypt library include directory if needed
      -- Example: "vendor/bcrypt/include"
   }

   libdirs
   {
      -- Add bcrypt library directory if needed
      -- Example: "vendor/bcrypt/lib"
   }

   links
   {
      "bcrypt"
   }

   filter "configurations:VAULT_DEBUG"
      defines { "VAULT_DEBUG", "UNICODE", "_UNICODE" }
      runtime "Debug"
      symbols "on"

   filter "configurations:VAULT_RELEASE"
      defines { "VAULT_RELEASE", "UNICODE", "_UNICODE" }
      runtime "Release"
      optimize "on"

   filter "configurations:VAULT_DIST"
      defines { "VAULT_DIST", "UNICODE", "_UNICODE" }
      runtime "Release"
      optimize "on"

   filter "system:windows"
      systemversion "latest"

      defines
      {
         "VAULT_PLATFORM_WINDOWS"
      }

   -- Set the character set to Unicode (UTF-8) for Windows
   filter { "system:windows", "language:C++" }
      characterset "Unicode"
