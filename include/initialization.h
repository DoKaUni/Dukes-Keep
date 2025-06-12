#pragma once

// SDL Main flag for compatibility with windows
#define SDL_MAIN_HANDLED

#include "imgui.h"
#include "backends/imgui_impl_sdl2.h"
#include "backends/imgui_impl_vulkan.h"
#include <SDL.h>
#include <SDL_vulkan.h>

#include <string>
#include <vector>

// Volk headers
#ifdef IMGUI_IMPL_VULKAN_USE_VOLK
#define VOLK_IMPLEMENTATION
#include <volk.h>
#endif

//#define APP_USE_UNLIMITED_FRAME_RATE
#ifdef _DEBUG
#define APP_USE_VULKAN_DEBUG_REPORT
#endif

// Data
extern VkAllocationCallbacks*   g_Allocator;
extern VkInstance               g_Instance;
extern VkPhysicalDevice         g_PhysicalDevice;
extern VkDevice                 g_Device;
extern uint32_t                 g_QueueFamily;
extern VkQueue                  g_Queue;
extern VkDebugReportCallbackEXT g_DebugReport;
extern VkPipelineCache          g_PipelineCache;
extern VkDescriptorPool         g_DescriptorPool;

extern ImGui_ImplVulkanH_Window g_MainWindowData;
extern uint32_t                 g_MinImageCount;
extern bool                     g_SwapChainRebuild;

void check_vk_result(VkResult err);
bool IsExtensionAvailable(const ImVector<VkExtensionProperties>& properties, const char* extension);
void SetupVulkan(ImVector<const char*> instance_extensions);
void SetupVulkanWindow(ImGui_ImplVulkanH_Window* wd, VkSurfaceKHR surface, int width, int height);
void CleanupVulkan();
void CleanupVulkanWindow();
void FrameRender(ImGui_ImplVulkanH_Window* wd, ImDrawData* draw_data);
void FramePresent(ImGui_ImplVulkanH_Window* wd);