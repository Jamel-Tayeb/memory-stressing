#include <assert.h>
#include <stdio.h>
#include <windows.h>

BOOL signal_handler(DWORD);
BOOL do_high_memory_use(unsigned int, unsigned int);

HANDLE h_stop = NULL;

BOOL main(int argc, char *argv[]) {

   //----------------------------------------------------------------------
   // Generic variables.
   //----------------------------------------------------------------------
   BOOL bret = TRUE;

   //----------------------------------------------------------------------
   // Load definition variables.
   //----------------------------------------------------------------------
   unsigned int load = 10;
   unsigned int load_duration_in_ms = 60000; // one minute

   //----------------------------------------------------------------------

   //----------------------------------------------------------------------
   // Extract options and generate the load.
   //----------------------------------------------------------------------
   if (argc > 1) {
      load = (unsigned int)atoi(argv[1]);
      if (argc > 2) {
         load_duration_in_ms = (unsigned int)atoi(argv[2]);
      }
      bret = do_high_memory_use(
         load,
         load_duration_in_ms
      );
   } else {
      (void)printf("Usage: stressmem <%%> .\n");
   }

   return(bret);

}

BOOL do_high_memory_use(
   unsigned int load, 
   unsigned int load_duration_in_ms
) {

   //----------------------------------------------------------------------
   // Generic variables.
   //----------------------------------------------------------------------
   DWORD dwret = 0;
   BOOL bret = FALSE;
   size_t memory_size = 0; // always in bytes

   //----------------------------------------------------------------------
   // Memory management variables.
   //----------------------------------------------------------------------
   int f_memory_mapped = 0;
   ULONG_PTR* PFN_array = NULL;
   PVOID reserved_memory = NULL;
   SYSTEM_INFO system_info = { 0 };
   size_t PFN_array_size_in_bytes = 0;
   ULONG_PTR requested_pages_count = 0;
   ULONG_PTR allocated_pages_count = 0;
   size_t requested_memory_in_bytes = 0;
   MEMORYSTATUSEX memory_status = { 0 };

   //----------------------------------------------------------------------
   // Signal variables.
   //----------------------------------------------------------------------
   int f_signal_handler_installed = 0;

   //----------------------------------------------------------------------
   // Privilege management variables.
   //----------------------------------------------------------------------
   HANDLE token = NULL;
   TOKEN_PRIVILEGES privilege = { 0 };

   //----------------------------------------------------------------------

   //----------------------------------------------------------------------
   // Get system info data.
   //----------------------------------------------------------------------
   (void)memset(
      &system_info,
      0,
      sizeof(system_info)
   );
   GetNativeSystemInfo(&system_info);

   //----------------------------------------------------------------------
   // Compute how many memory pages are needed.
   //----------------------------------------------------------------------
   (void)memset(
      &memory_status,
      0,
      sizeof(memory_status)
   );
   memory_status.dwLength = sizeof(memory_status);
   bret = GlobalMemoryStatusEx(&memory_status);
   if(bret == FALSE) {
      goto do_high_memory_use_exit;
   }
   //----------------------------------------------------------------------
   requested_memory_in_bytes = (size_t)(
      (
         memory_status.ullTotalPhys / // in bytes
         100.0
      ) *
      load // in %
   );
   requested_pages_count = (ULONG_PTR)(
      requested_memory_in_bytes /
      system_info.dwPageSize // assumed in bytes (not documented)
   );
   if (requested_pages_count == 0) {
      requested_pages_count = 1;
   }

   //----------------------------------------------------------------------
   // Allocate PFNs. PFN = Page Frame Number.
   //----------------------------------------------------------------------
   memory_size = requested_pages_count * sizeof(ULONG_PTR);
   assert(memory_size > 0);
   PFN_array_size_in_bytes = memory_size;
   PFN_array = (ULONG_PTR*)HeapAlloc(
      GetProcessHeap(),
      0,
      PFN_array_size_in_bytes
   );
   if (PFN_array == NULL) {
      goto do_high_memory_use_exit;
   }
   (void)memset(
      PFN_array,
      0,
      PFN_array_size_in_bytes
   );

   //----------------------------------------------------------------------
   // Set privilege.
   // Note:
   // to add SE_LOCK_MEMORY_NAME privilege, the user must have the "Lock
   // pages in memory" right. This can be added in: Control Panel > Local
   // Security policy > Local Policies > User Rights Assignment > Lock
   // pages in memory. Once set, the user needs to log-off and then log-on.
   //----------------------------------------------------------------------
   bret = OpenProcessToken(
      GetCurrentProcess(),
      TOKEN_ADJUST_PRIVILEGES,
      &token
   );
   if (bret == FALSE) {
      goto do_high_memory_use_exit;
   }
   //----------------------------------------------------------------------
   (void)memset(
      &privilege,
      0,
      sizeof(privilege)
   );
   privilege.PrivilegeCount = 1;
   privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
   bret = LookupPrivilegeValue(
      NULL,
      SE_LOCK_MEMORY_NAME,
      &privilege.Privileges[0].Luid
   );
   if (bret == FALSE) {
      goto do_high_memory_use_exit;
   }
   //----------------------------------------------------------------------
   bret = AdjustTokenPrivileges(
      token,
      FALSE,
      (PTOKEN_PRIVILEGES)&privilege,
      0,
      NULL,
      NULL
   );
   if (bret == FALSE) {
      goto do_high_memory_use_exit;
   }
   if (GetLastError() != ERROR_SUCCESS) {
      goto do_high_memory_use_exit;
   }
   //----------------------------------------------------------------------
   if (token != NULL) {
      bret = CloseHandle(token);
      if (bret == FALSE) {
         goto do_high_memory_use_exit;
      }
      token = NULL;
   }

   //----------------------------------------------------------------------
   // Allocate physical memory.
   //----------------------------------------------------------------------
   allocated_pages_count = requested_pages_count;
   bret = AllocateUserPhysicalPages(
      GetCurrentProcess(),
      &requested_pages_count,
      PFN_array
   );
   if (bret == FALSE) {
      goto do_high_memory_use_exit;
   }
   if (allocated_pages_count != requested_pages_count) {
      ; // Warning, did not get all the requested memory!
   }

   //----------------------------------------------------------------------
   // Allocate virtual memory (do not use or clear).
   //----------------------------------------------------------------------
   reserved_memory = VirtualAlloc(
      NULL,
      requested_memory_in_bytes,
      MEM_RESERVE | MEM_PHYSICAL,
      PAGE_READWRITE
   );
   if (reserved_memory == NULL) {
      goto do_high_memory_use_exit;
   }

   //----------------------------------------------------------------------
   // Map physical memory.
   //----------------------------------------------------------------------
   f_memory_mapped = 0;
   bret = MapUserPhysicalPages(
      reserved_memory,
      requested_pages_count,
      PFN_array
   );
   if (bret == FALSE) {
      goto do_high_memory_use_exit;
   }
   f_memory_mapped = 1;

   //----------------------------------------------------------------------
   // Setup signal handler.
   //----------------------------------------------------------------------
   h_stop = CreateEvent(
      NULL,
      TRUE, // manual reset,
      FALSE, // not signaled,
      NULL
   );
   if (h_stop == NULL) {
      goto do_high_memory_use_exit;

   }
   //----------------------------------------------------------------------
   bret = SetConsoleCtrlHandler(
      (PHANDLER_ROUTINE)signal_handler,
      TRUE
   );
   if (bret == FALSE) {
      goto do_high_memory_use_exit;
   }
   //----------------------------------------------------------------------
   f_signal_handler_installed = 1;

   //----------------------------------------------------------------------
   // Wait for duration or stop.
   //----------------------------------------------------------------------
   assert(h_stop != NULL);
   assert(load_duration_in_ms > 0.0);
   (void)WaitForSingleObject(
      h_stop,
      (DWORD)load_duration_in_ms
   );

do_high_memory_use_exit:

   //----------------------------------------------------------------------
   // Uninstall the signals handler routine.
   //----------------------------------------------------------------------
   if (f_signal_handler_installed == 1) {
      (void)SetConsoleCtrlHandler(
         (PHANDLER_ROUTINE)signal_handler,
         FALSE
      );
      f_signal_handler_installed = 0;
   }
   //----------------------------------------------------------------------
   if (h_stop != NULL) {
      (void)CloseHandle(h_stop);
      h_stop = NULL;
   }

   //----------------------------------------------------------------------
   // Un-map physical memory.
   //----------------------------------------------------------------------
   if (f_memory_mapped == 1) {
      (void)MapUserPhysicalPages(
         reserved_memory,
         requested_pages_count,
         NULL
      );
   }

   //----------------------------------------------------------------------
   // Free physical memory.
   //----------------------------------------------------------------------
   if (PFN_array != NULL) {
      (void)FreeUserPhysicalPages(
         GetCurrentProcess(),
         &requested_pages_count,
         PFN_array
      );
   }

   //----------------------------------------------------------------------
   // Free virtual memory.
   //----------------------------------------------------------------------
   if (reserved_memory != NULL) {
      (void)VirtualFree(
         reserved_memory,
         0,
         MEM_RELEASE
      );
      reserved_memory = NULL;
   }

   //----------------------------------------------------------------------
   // Free PFN array.
   //----------------------------------------------------------------------
   if (PFN_array != NULL) {
      (void)HeapFree(
         GetProcessHeap(),
         0,
         PFN_array
      );
      PFN_array = NULL;
   }

   return(TRUE);

}

BOOL signal_handler(DWORD c) {

   //----------------------------------------------------------------------
   // Generic variables.
   //----------------------------------------------------------------------
   BOOL bret = FALSE;

   //----------------------------------------------------------------------

   //----------------------------------------------------------------------
   // Handle request.
   //----------------------------------------------------------------------
   switch (c) {

      case CTRL_LOGOFF_EVENT: // fall through
      case CTRL_SHUTDOWN_EVENT: // fall through
      case CTRL_C_EVENT:
         if (h_stop != NULL) {
            bret = SetEvent(h_stop);
            if (bret == FALSE) {
               goto signal_handler_exit;
            }
         }
         return(TRUE);
         break;

      default:
         return(FALSE);
   } // switch

signal_handler_exit:

   return(FALSE);

}
</windows.h></stdio.h></assert.h>
