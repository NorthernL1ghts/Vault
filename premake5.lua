workspace "Vault"
   architecture "x64"
   startproject "Vault"

   configurations
   {
      "Debug",
      "Release",
      "Dist"
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
      "VAULT_PLATFORM_WINDOWS"
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

   filter "configurations:Debug"
      defines "VAULT_DEBUG"
      runtime "Debug"
      symbols "on"

   filter "configurations:Release"
      defines "VAULT_RELEASE"
      runtime "Release"
      optimize "on"

   filter "configurations:Dist"
      defines "VAULT_DIST"
      runtime "Release"
      optimize "on"

   filter "system:windows"
      systemversion "latest"

      defines
      {
         "VAULT_PLATFORM_WINDOWS"
      }