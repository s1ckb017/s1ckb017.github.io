# Discover an AntiDebug feature: a newbie approach

This blogpost shows the way I understod where the anti debug check were implemented with a basic, I would say, tending to 0, knowledge on Windows Internals.
I started from a problem: the target process I wanted to attach was protected by a kind of watchdog. Did not know if the watchdog was in kernel space or in user space. During this journey, I learnt something about *Windows internals*, *x64dbg/titan engine* internals and improved windbg usage.

## Problem: Access DENIED to process

I wanted to debug a service running with elevated privilege, i.e. SYSTEM, but this seems to be impossible even using x32dbg run as SYSTEM user.
<br>
<p align="center">
  <img width="460" height="100" src="/assets/images/post_2022_07_30/img1.PNG">
</p>

Running x32dbg with system privileges and attaching to the process results in an *ACCESS DENIED* error.
The PID to debug is *4056*.
<br>
<p align="center">
  <img  src="/assets/images/post_2022_07_30/img2.PNG">
</p>

So, to understand where the debugger received the *ACCESS DENIED*, I started digging into the procedure used by the debugger to attach and debug a process.
<br>
<p align="center">
  <img width="460" height="300" src="/assets/images/post_2022_07_30/meme.jpg">
</p>

First thing, I did, is to put a *bp on ntOpenProcess()*. I was pretty sure that *ntOpenProcess()* was the first involved routine.
In the following image is clear that the debugger under debug is opening the target process.
<br>
<p align="center">
  <img width=1200 src="/assets/images/post_2022_07_30/img3.PNG">
</p>
<br>
<p align="center">
  <img width=1200  src="/assets/images/post_2022_07_30/img_op.PNG">
</p>
<br>

The *ntOpenProcess()* returns a valid handle, as shown in the image, this suggested that the process is correctly opened.
<br>
<p align="center">
  <img  width=1200  src="/assets/images/post_2022_07_30/img_op2.PNG">
</p>
<br>

So, then I cross searched in titan engine and in the x64 debugger source code where this call happens and what there is after.
After some research I found that the failing function was [DbgUiDebugActiveProcess_(IN HANDLE Process)](https://github.com/x64dbg/TitanEngine/blob/fb1babcbb31808413f238ab27d2cc571d07f9481/TitanEngine/Global.Debugger.cpp)), i.e. the systemcall *NtDebugActiveProcess()* returned *ACCESS DENIED*
<br>

<p align="center">
  <img width=1200  src="/assets/images/post_2022_07_30/img_op3.PNG">
</p>
<p align="center">
  <img  width=1200  src="/assets/images/post_2022_07_30/img_op4.PNG">
</p>
<br>

This is a function exported by ntdll.dll and ends directly in kernel space without any intermediate. Moreover, checking the target binary statically seems that did not exists any anti debug trick implemented inside.
</br>

` OpenProcess() returns no error + NtDebugActiveProcess() return ACCESS DENIED + No anti debug in target binary -> check most likely in kernel space `
<br>
Just to see if some of these functions is called and cause an access denied.
<br>

## Test case

At this point, I focused my research on kernel space in order to check why that routine return *ACCESS DENIED* even though the process has been correctly opened.
If exists some anti debug trick in kernel space that would not allow to debug a process then it would deny any injection too.
So, to have a better test case I wrote a small snippet in C that open a process and inject a DLL. 
<br>

```
	HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, false, pId);
	if (h) {
		printf("[+] Process %d Opened handle no. %08x\n", pId, (unsigned int)h);
		LPVOID LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		printf("[+] LoadLibraryA address: %p\n", LoadLibAddr);
		getchar();
		LPVOID dereercomp = VirtualAllocEx(h, NULL, strlen(dllName)+1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (dereercomp == NULL)
		{
			fprintf(stderr, "[-] Impossible allocate new memory in the target process %d\n", GetLastError());
			return 1;
		}
		printf("[+] Alloced space on: %p\n", dereercomp);
		if (!WriteProcessMemory(h, dereercomp, dllName, strlen(dllName), NULL)) {
			fprintf(stderr, "[-] Impossible writing in process memory %d\n", GetLastError());
			return 1;
		}
		else {
			printf("[+] Process memory correctly written\n");
		}
		HANDLE asdc = CreateRemoteThread(h, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, dereercomp, 0, NULL);
		printf("[+] Remote Thread Output: %d %d\n", asdc, GetLastError());
		WaitForSingleObject(asdc, INFINITE);
		VirtualFreeEx(h, dereercomp, strlen(dllName), MEM_RELEASE);
		CloseHandle(asdc);
		CloseHandle(h);
		return 0;
	}
```
<br>

Running the test case against the process pid from an elevated powershell results in *ACCESS DENIED* too on *VirtualAllocEx()* routine.
<br>
<p align="center">
  <img src="/assets/images/post_2022_07_30/img5.PNG">
</p>
<br>
<br>

## Windows Kernel Debugging: searching for the anti debug 

<br>

At this point, I started to debug the windows kernel using windbg, so I decided, firstly to inspect a bit the target process.
<br>

```
kd> !process 0xfd8
Searching for Process with Cid == fd8
PROCESS ffffc20239807080
    SessionId: 0  Cid: 0fd8    Peb: 00256000  ParentCid: 0270
    DirBase: 1ce063000  ObjectTable: ffff89020ea49180  HandleCount: 357.
    VadRoot ffffc2023704ee50 Vads 163 Clone 0 Private 1876. Modified 125. Locked 0.
    DeviceMap ffff890205035ae0
    Token                             ffff89020e225060
    ElapsedTime                       17:06:01.856
    UserTime                          00:00:00.312
    KernelTime                        00:00:00.187
    QuotaPoolUsage[PagedPool]         628552
    QuotaPoolUsage[NonPagedPool]      23512
    Working Set Sizes (now,min,max)  (56976, 50, 345) (227904KB, 200KB, 1380KB)
    PeakWorkingSetSize                84807
    VirtualSize                       322 Mb
    PeakVirtualSize                   419 Mb
    PageFaultCount                    126060
    MemoryPriority                    BACKGROUND
    BasePriority                      8
    CommitCharge                      11044
```
<br>

According to flags, *BeingDebugged and NtGlobalFlag*, contained in the process environment block data structure, seems that the process is not currently under debug of another process.
<br>

A great article on this topic is provided by [*CheckPoint Research*](https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-peb-beingdebugged-flag) 
<br>

```
kd> .process /p ffffc20239807080; !peb 00256000
Implicit process is now ffffc202`39807080
.cache forcedecodeuser done
PEB at 0000000000256000
    InheritedAddressSpace:    No
    ReadImageFileExecOptions: No
    BeingDebugged:            No
    ImageBaseAddress:         0000000000400000
    NtGlobalFlag:             0
    NtGlobalFlag2:            0
    Ldr                       00007fff9f8ba4c0
    Ldr.Initialized:          Yes
    Ldr.InInitializationOrderModuleList: 00000000005627a0 . 0000000000562ff0
    Ldr.InLoadOrderModuleList:           0000000000562910 . 0000000000562fd0
    Ldr.InMemoryOrderModuleList:         0000000000562920 . 0000000000562fe0

kd> dt _peb 0x0256000
win32k!_PEB
   +0x000 InheritedAddressSpace : 0 ''
   +0x001 ReadImageFileExecOptions : 0 ''
   +0x002 BeingDebugged    : 0 ''
   +0x003 BitField         : 0 ''
    ...
   +0x0b8 NumberOfProcessors : 1
   +0x0bc NtGlobalFlag     : 0
   +0x0c0 CriticalSectionTimeout : _LARGE_INTEGER 0xffffe86d`079b8000
   +0x0c8 HeapSegmentReserve : 0x100000
   +0x0d0 HeapSegmentCommit : 0x2000
   +0x0d8 HeapDeCommitTotalFreeThreshold : 0x10000
   +0x0e0 HeapDeCommitFreeBlockThreshold : 0x1000
   +0x0e8 NumberOfHeaps    : 2
   +0x0ec MaximumNumberOfHeaps : 0x10
   +0x0f0 ProcessHeaps     : 0x00007fff`9f8b8d40  -> 0x00000000`00560000 Void
    ...
   +0x7c4 NtGlobalFlag2    : 0

```
<br>

At this point, I checked the *eprocess structure*.
<br>

```
kd> dt ffffc20239807080  _eprocess
nt!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x438 ProcessLock      : _EX_PUSH_LOCK
   +0x440 UniqueProcessId  : 0x00000000`00000fd8 Void
   +0x448 ActiveProcessLinks : _LIST_ENTRY [ 0xffffc202`39bc84c8 - 0xffffc202`370b54c8 ]
   +0x458 RundownProtect   : _EX_RUNDOWN_REF
   +0x460 Flags2           : 0xd000
   +0x464 Flags            : 0x144d0c01
   +0x464 CreateReported   : 0y1
   +0x464 NoDebugInherit   : 0y0
   +0x464 ProcessExiting   : 0y0
   +0x464 ProcessDelete    : 0y0
   +0x464 ManageExecutableMemoryWrites : 0y0
   +0x464 VmDeleted        : 0y0
   +0x464 OutswapEnabled   : 0y0
   +0x464 Outswapped       : 0y0
   +0x464 FailFastOnCommitFail : 0y0
   +0x464 Wow64VaSpace4Gb  : 0y0
   +0x464 AddressSpaceInitialized : 0y11
   +0x464 SetTimerResolution : 0y0
   +0x464 BreakOnTermination : 0y0
   +0x464 DeprioritizeViews : 0y0
   +0x464 WriteWatch       : 0y0
   +0x464 ProcessInSession : 0y1
   +0x464 OverrideAddressSpace : 0y0
   +0x464 HasAddressSpace  : 0y1
   +0x464 LaunchPrefetched : 0y1
   +0x464 Background       : 0y0
   +0x464 VmTopDown        : 0y0
   +0x464 ImageNotifyDone  : 0y1
   +0x464 PdeUpdateNeeded  : 0y0
   +0x464 VdmAllowed       : 0y0
   +0x464 ProcessRundown   : 0y0
   +0x464 ProcessInserted  : 0y1
   +0x464 DefaultIoPriority : 0y010
   +0x464 ProcessSelfDelete : 0y0
   +0x464 SetTimerResolutionLink : 0y0
   +0x468 CreateTime       : _LARGE_INTEGER 0x01d879aa`94a2629d
    ...
   +0x550 Peb              : 0x00000000`00256000 _PEB
   +0x558 Session          : 0xffffd280`69c5b000 _MM_SESSION_SPACE
   +0x560 Spare1           : (null) 
   +0x568 QuotaBlock       : 0xfffff806`12053800 _EPROCESS_QUOTA_BLOCK
   +0x570 ObjectTable      : 0xffff8902`0ea49180 _HANDLE_TABLE
   +0x578 DebugPort        : (null) 
   +0x580 WoW64Process     : 0xffffc202`350fed50 _EWOW64PROCESS
```
<br>

The *DebugPort* is null so seems there is no debug object linked to the target process.
<br>

At this point, I set a breakpoint on virtual alloc system call handler in kernel space when the handle is equal to the handle number used by the test case, i.e. *0xc4*.
In this way, I could stop the OS when the *VirtualAllocEx()* called by the test case enter in kernel space.
<br>

` bp /w "@ecx == 0xc4" nt!NtAllocateVirtualMemory `
<br>
<p align="center">
  <img src="/assets/images/post_2022_07_30/img6_.png">
</p>
<br>

So, I traced every instruction until return of the *nt!NtAllocateVirtualMemory()* using the command: *ta fffff806`11ab6940*.
<br>
<p align="center">
  <img src="/assets/images/post_2022_07_30/img7.PNG">
</p>
<br>

*RAX* at the end contain the value of the *ACCESS DENIED* error, i.e. *0x00000000c0000022*.
<br>

Looking the trace from the end, has been identified where the return value is set.
<br>

```
nt!ObpReferenceObjectByHandleWithTag+0x4e8:
fffff806`119f61b8 8bc7            mov     eax,edi
nt!ObpReferenceObjectByHandleWithTag+0x4ea:
fffff806`119f61ba e944fdffff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x233 (fffff806`119f5f03)
nt!ObpReferenceObjectByHandleWithTag+0x233:
fffff806`119f5f03 4c8b742448      mov     r14,qword ptr [rsp+48h]
nt!ObpReferenceObjectByHandleWithTag+0x238:
fffff806`119f5f08 488b6c2450      mov     rbp,qword ptr [rsp+50h]
nt!ObpReferenceObjectByHandleWithTag+0x23d:
fffff806`119f5f0d 4883c458        add     rsp,58h
nt!ObpReferenceObjectByHandleWithTag+0x241:
fffff806`119f5f11 415f            pop     r15
nt!ObpReferenceObjectByHandleWithTag+0x243:
fffff806`119f5f13 415d            pop     r13
nt!ObpReferenceObjectByHandleWithTag+0x245:
fffff806`119f5f15 415c            pop     r12
nt!ObpReferenceObjectByHandleWithTag+0x247:
fffff806`119f5f17 5f              pop     rdi
nt!ObpReferenceObjectByHandleWithTag+0x248:
fffff806`119f5f18 5e              pop     rsi
nt!ObpReferenceObjectByHandleWithTag+0x249:
fffff806`119f5f19 5b              pop     rbx
nt!ObpReferenceObjectByHandleWithTag+0x24a:
fffff806`119f5f1a c3              ret
nt!MiAllocateVirtualMemoryPrepare+0x4e3:
fffff806`11ab73d3 448bf0          mov     r14d,eax
nt!MiAllocateVirtualMemoryPrepare+0x4e6:
fffff806`11ab73d6 85c0            test    eax,eax
nt!MiAllocateVirtualMemoryPrepare+0x4e8:
fffff806`11ab73d8 0f880e841500    js      nt!MiAllocateVirtualMemoryPrepare+0x1588fc (fffff806`11c0f7ec)
nt!MiAllocateVirtualMemoryPrepare+0x1588fc:
fffff806`11c0f7ec 488b442448      mov     rax,qword ptr [rsp+48h]
nt!MiAllocateVirtualMemoryPrepare+0x158901:
fffff806`11c0f7f1 4885c0          test    rax,rax
nt!MiAllocateVirtualMemoryPrepare+0x158904:
fffff806`11c0f7f4 740d            je      nt!MiAllocateVirtualMemoryPrepare+0x158913 (fffff806`11c0f803)
nt!MiAllocateVirtualMemoryPrepare+0x158913:
fffff806`11c0f803 418bc6          mov     eax,r14d
nt!MiAllocateVirtualMemoryPrepare+0x158916:
fffff806`11c0f806 e9327aeaff      jmp     nt!MiAllocateVirtualMemoryPrepare+0x34d (fffff806`11ab723d)
nt!MiAllocateVirtualMemoryPrepare+0x34d:
fffff806`11ab723d 488b9c24b8000000 mov     rbx,qword ptr [rsp+0B8h]
nt!MiAllocateVirtualMemoryPrepare+0x355:
fffff806`11ab7245 4883c460        add     rsp,60h
nt!MiAllocateVirtualMemoryPrepare+0x359:
fffff806`11ab7249 415f            pop     r15
nt!MiAllocateVirtualMemoryPrepare+0x35b:
fffff806`11ab724b 415e            pop     r14
nt!MiAllocateVirtualMemoryPrepare+0x35d:
fffff806`11ab724d 415d            pop     r13
nt!MiAllocateVirtualMemoryPrepare+0x35f:
fffff806`11ab724f 415c            pop     r12
nt!MiAllocateVirtualMemoryPrepare+0x361:
fffff806`11ab7251 5f              pop     rdi
nt!MiAllocateVirtualMemoryPrepare+0x362:
fffff806`11ab7252 5e              pop     rsi
nt!MiAllocateVirtualMemoryPrepare+0x363:
fffff806`11ab7253 5d              pop     rbp
nt!MiAllocateVirtualMemoryPrepare+0x364:
fffff806`11ab7254 c3              ret
nt!NtAllocateVirtualMemory+0x16a:
fffff806`11ab688a 8bd8            mov     ebx,eax
nt!NtAllocateVirtualMemory+0x16c:
fffff806`11ab688c 89442474        mov     dword ptr [rsp+74h],eax
nt!NtAllocateVirtualMemory+0x170:
fffff806`11ab6890 85c0            test    eax,eax
nt!NtAllocateVirtualMemory+0x172:
fffff806`11ab6892 7861            js      nt!NtAllocateVirtualMemory+0x1d5 (fffff806`11ab68f5)
nt!NtAllocateVirtualMemory+0x1d5:
fffff806`11ab68f5 85db            test    ebx,ebx
nt!NtAllocateVirtualMemory+0x1d7:
fffff806`11ab68f7 7855            js      nt!NtAllocateVirtualMemory+0x22e (fffff806`11ab694e)
nt!NtAllocateVirtualMemory+0x22e:
fffff806`11ab694e 4883bc240001000000 cmp   qword ptr [rsp+100h],0
nt!NtAllocateVirtualMemory+0x237:
fffff806`11ab6957 0f84578d1500    je      nt!NtAllocateVirtualMemory+0x158f94 (fffff806`11c0f6b4)
nt!NtAllocateVirtualMemory+0x158f94:
fffff806`11c0f6b4 ff05eeee4300    inc     dword ptr [nt!MiState+0x1f28 (fffff806`1204e5a8)]
nt!NtAllocateVirtualMemory+0x158f9a:
fffff806`11c0f6ba e93a72eaff      jmp     nt!NtAllocateVirtualMemory+0x1d9 (fffff806`11ab68f9)
nt!NtAllocateVirtualMemory+0x1d9:
fffff806`11ab68f9 4983fe02        cmp     r14,2
nt!NtAllocateVirtualMemory+0x1dd:
fffff806`11ab68fd 0f83bc8d1500    jae     nt!NtAllocateVirtualMemory+0x158f9f (fffff806`11c0f6bf)
nt!NtAllocateVirtualMemory+0x1e3:
fffff806`11ab6903 488b8c2498000000 mov     rcx,qword ptr [rsp+98h]
nt!NtAllocateVirtualMemory+0x1eb:
fffff806`11ab690b 4885c9          test    rcx,rcx
nt!NtAllocateVirtualMemory+0x1ee:
fffff806`11ab690e 7532            jne     nt!NtAllocateVirtualMemory+0x222 (fffff806`11ab6942)
nt!NtAllocateVirtualMemory+0x1f0:
fffff806`11ab6910 85db            test    ebx,ebx
nt!NtAllocateVirtualMemory+0x1f2:
fffff806`11ab6912 780e            js      nt!NtAllocateVirtualMemory+0x202 (fffff806`11ab6922)
nt!NtAllocateVirtualMemory+0x202:
fffff806`11ab6922 8bc3            mov     eax,ebx
nt!NtAllocateVirtualMemory+0x204:
fffff806`11ab6924 4c8d9c2480010000 lea     r11,[rsp+180h]
nt!NtAllocateVirtualMemory+0x20c:
fffff806`11ab692c 498b5b38        mov     rbx,qword ptr [r11+38h]
nt!NtAllocateVirtualMemory+0x210:
fffff806`11ab6930 498b7348        mov     rsi,qword ptr [r11+48h]
nt!NtAllocateVirtualMemory+0x214:
fffff806`11ab6934 498be3          mov     rsp,r11
nt!NtAllocateVirtualMemory+0x217:
fffff806`11ab6937 415f            pop     r15
nt!NtAllocateVirtualMemory+0x219:
fffff806`11ab6939 415e            pop     r14
nt!NtAllocateVirtualMemory+0x21b:
fffff806`11ab693b 415d            pop     r13
nt!NtAllocateVirtualMemory+0x21d:
fffff806`11ab693d 415c            pop     r12
nt!NtAllocateVirtualMemory+0x21f:
fffff806`11ab693f 5f              pop     rdi
nt!NtAllocateVirtualMemory+0x220:
fffff806`11ab6940 c3              ret
```
<br>

Basically, *edi* is set into *eax* at *nt!ObpReferenceObjectByHandleWithTag+0x4e8* and even though there are many register movements at the end *nt!NtAllocateVirtualMemory+0x220* has in *RAX* the value contained by *edi* at *nt!ObpReferenceObjectByHandleWithTag+0x4e8*.
<br>

Looking further back, it's clear that *edi* is set to the *ACCESS DENIED* value.

```
fffff806`119f5e99 0f85ee020000    jne     nt!ObpReferenceObjectByHandleWithTag+0x4bd (fffff806`119f618d)
nt!ObpReferenceObjectByHandleWithTag+0x4bd:
fffff806`119f618d bf220000c0      mov     edi,0C0000022h
nt!ObpReferenceObjectByHandleWithTag+0x4c2:
fffff806`119f6192 8b9424b0000000  mov     edx,dword ptr [rsp+0B0h]
nt!ObpReferenceObjectByHandleWithTag+0x4c9:
fffff806`119f6199 488d4b30        lea     rcx,[rbx+30h]
nt!ObpReferenceObjectByHandleWithTag+0x4cd:
fffff806`119f619d e8ee20c1ff      call    nt!ObfDereferenceObjectWithTag (fffff806`11608290)
nt!ObpReferenceObjectByHandleWithTag+0x4d2:
fffff806`119f61a2 80bc24b800000000 cmp     byte ptr [rsp+0B8h],0
nt!ObpReferenceObjectByHandleWithTag+0x4da:
fffff806`119f61aa 0f858bb61e00    jne     nt!ObpReferenceObjectByHandleWithTag+0x1ebb6b (fffff806`11be183b)
nt!ObpReferenceObjectByHandleWithTag+0x4e0:
fffff806`119f61b0 498bcf          mov     rcx,r15
nt!ObpReferenceObjectByHandleWithTag+0x4e3:
fffff806`119f61b3 e8584ec1ff      call    nt!KeLeaveCriticalRegionThread (fffff806`1160b010)
nt!ObpReferenceObjectByHandleWithTag+0x4e8:
fffff806`119f61b8 8bc7            mov     eax,edi
```
<br>

[Microsoft](https://docs.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-170#x64-register-usage) says that *RDI* register should be preserved by the callee and indeed it is through the calls to *call   nt!ObfDereferenceObjectWithTag* and *call    nt!KeLeaveCriticalRegionThread*.
<br>

*RDI*, is preserved in *nt!ObfDereferenceObjectWithTag*, even if it is never touched, pushing it on the stack and popping it at the end.

```
nt!ObfDereferenceObjectWithTag:
fffff806`11608290 48895c2408      mov     qword ptr [rsp+8],rbx
nt!ObfDereferenceObjectWithTag+0x5:
fffff806`11608295 4889742410      mov     qword ptr [rsp+10h],rsi
nt!ObfDereferenceObjectWithTag+0xa:
fffff806`1160829a 57              push    rdi
nt!ObfDereferenceObjectWithTag+0xb:
fffff806`1160829b 4883ec30        sub     rsp,30h
nt!ObfDereferenceObjectWithTag+0xf:
fffff806`1160829f 833d6a2daf0000  cmp     dword ptr [nt!ObpTraceFlags (fffff806`120fb010)],0
nt!ObfDereferenceObjectWithTag+0x16:
fffff806`116082a6 488bf1          mov     rsi,rcx
nt!ObfDereferenceObjectWithTag+0x19:
fffff806`116082a9 0f8525f22000    jne     nt!ObfDereferenceObjectWithTag+0x20f244 (fffff806`118174d4)
nt!ObfDereferenceObjectWithTag+0x1f:
fffff806`116082af 48c7c3ffffffff  mov     rbx,0FFFFFFFFFFFFFFFFh
nt!ObfDereferenceObjectWithTag+0x26:
fffff806`116082b6 f0480fc15ed0    lock xadd qword ptr [rsi-30h],rbx
nt!ObfDereferenceObjectWithTag+0x2c:
fffff806`116082bc 4883eb01        sub     rbx,1
nt!ObfDereferenceObjectWithTag+0x30:
fffff806`116082c0 7e14            jle     nt!ObfDereferenceObjectWithTag+0x46 (fffff806`116082d6)
nt!ObfDereferenceObjectWithTag+0x32:
fffff806`116082c2 488bc3          mov     rax,rbx
nt!ObfDereferenceObjectWithTag+0x35:
fffff806`116082c5 488b5c2440      mov     rbx,qword ptr [rsp+40h]
nt!ObfDereferenceObjectWithTag+0x3a:
fffff806`116082ca 488b742448      mov     rsi,qword ptr [rsp+48h]
nt!ObfDereferenceObjectWithTag+0x3f:
fffff806`116082cf 4883c430        add     rsp,30h
nt!ObfDereferenceObjectWithTag+0x43:
fffff806`116082d3 5f              pop     rdi
nt!ObfDereferenceObjectWithTag+0x44:
fffff806`116082d4 c3              ret
```
<br>

In the *nt!KeLeaveCriticalRegionThread()*, *RDI* is preserved since it is never touched.

```
nt!KeLeaveCriticalRegionThread:
fffff806`1160b010 4883ec28        sub     rsp,28h
nt!KeLeaveCriticalRegionThread+0x4:
fffff806`1160b014 668381e401000001 add     word ptr [rcx+1E4h],1
nt!KeLeaveCriticalRegionThread+0xc:
fffff806`1160b01c 750c            jne     nt!KeLeaveCriticalRegionThread+0x1a (fffff806`1160b02a)
nt!KeLeaveCriticalRegionThread+0xe:
fffff806`1160b01e 488d8198000000  lea     rax,[rcx+98h]
nt!KeLeaveCriticalRegionThread+0x15:
fffff806`1160b025 483900          cmp     qword ptr [rax],rax
nt!KeLeaveCriticalRegionThread+0x18:
fffff806`1160b028 7506            jne     nt!KeLeaveCriticalRegionThread+0x20 (fffff806`1160b030)
nt!KeLeaveCriticalRegionThread+0x1a:
fffff806`1160b02a 4883c428        add     rsp,28h
nt!KeLeaveCriticalRegionThread+0x1e:
fffff806`1160b02e c3              ret
```
<br>

At this point, it's required to understand why *nt!ObpReferenceObjectByHandleWithTag+0x4bd* is executed!

```
nt!ExpLookupHandleTableEntry+0x30:
fffff806`119f62f0 c3              ret
nt!ObpReferenceObjectByHandleWithTag+0xef:
fffff806`119f5dbf 488bf8          mov     rdi,rax
nt!ObpReferenceObjectByHandleWithTag+0xf2:
fffff806`119f5dc2 4885c0          test    rax,rax
nt!ObpReferenceObjectByHandleWithTag+0xf5:
fffff806`119f5dc5 0f840b040000    je      nt!ObpReferenceObjectByHandleWithTag+0x506 (fffff806`119f61d6)
nt!ObpReferenceObjectByHandleWithTag+0xfb:
fffff806`119f5dcb 0f0d08          prefetchw [rax]
nt!ObpReferenceObjectByHandleWithTag+0xfe:
fffff806`119f5dce 488b08          mov     rcx,qword ptr [rax]
nt!ObpReferenceObjectByHandleWithTag+0x101:
fffff806`119f5dd1 488b6808        mov     rbp,qword ptr [rax+8]
nt!ObpReferenceObjectByHandleWithTag+0x105:
fffff806`119f5dd5 48896c2438      mov     qword ptr [rsp+38h],rbp
nt!ObpReferenceObjectByHandleWithTag+0x10a:
fffff806`119f5dda 48894c2430      mov     qword ptr [rsp+30h],rcx
nt!ObpReferenceObjectByHandleWithTag+0x10f:
fffff806`119f5ddf 4c8b742430      mov     r14,qword ptr [rsp+30h]
nt!ObpReferenceObjectByHandleWithTag+0x114:
fffff806`119f5de4 49f7c6feff0100  test    r14,1FFFEh
nt!ObpReferenceObjectByHandleWithTag+0x11b:
fffff806`119f5deb 0f84ff010000    je      nt!ObpReferenceObjectByHandleWithTag+0x320 (fffff806`119f5ff0)
nt!ObpReferenceObjectByHandleWithTag+0x121:
fffff806`119f5df1 41f6c601        test    r14b,1
nt!ObpReferenceObjectByHandleWithTag+0x125:
fffff806`119f5df5 0f8451030000    je      nt!ObpReferenceObjectByHandleWithTag+0x47c (fffff806`119f614c)
nt!ObpReferenceObjectByHandleWithTag+0x12b:
fffff806`119f5dfb 498d5efe        lea     rbx,[r14-2]
nt!ObpReferenceObjectByHandleWithTag+0x12f:
fffff806`119f5dff 488bcd          mov     rcx,rbp
nt!ObpReferenceObjectByHandleWithTag+0x132:
fffff806`119f5e02 498bc6          mov     rax,r14
nt!ObpReferenceObjectByHandleWithTag+0x135:
fffff806`119f5e05 488bd5          mov     rdx,rbp
nt!ObpReferenceObjectByHandleWithTag+0x138:
fffff806`119f5e08 f0480fc70f      lock cmpxchg16b oword ptr [rdi]
nt!ObpReferenceObjectByHandleWithTag+0x13d:
fffff806`119f5e0d 4c8bf0          mov     r14,rax
nt!ObpReferenceObjectByHandleWithTag+0x140:
fffff806`119f5e10 4889442430      mov     qword ptr [rsp+30h],rax
nt!ObpReferenceObjectByHandleWithTag+0x145:
fffff806`119f5e15 488bea          mov     rbp,rdx
nt!ObpReferenceObjectByHandleWithTag+0x148:
fffff806`119f5e18 4889542438      mov     qword ptr [rsp+38h],rdx
nt!ObpReferenceObjectByHandleWithTag+0x14d:
fffff806`119f5e1d 0f8558030000    jne     nt!ObpReferenceObjectByHandleWithTag+0x4ab (fffff806`119f617b)
nt!ObpReferenceObjectByHandleWithTag+0x153:
fffff806`119f5e23 488bd8          mov     rbx,rax
nt!ObpReferenceObjectByHandleWithTag+0x156:
fffff806`119f5e26 48d1eb          shr     rbx,1
nt!ObpReferenceObjectByHandleWithTag+0x159:
fffff806`119f5e29 6683fb10        cmp     bx,10h
nt!ObpReferenceObjectByHandleWithTag+0x15d:
fffff806`119f5e2d 0f84e4030000    je      nt!ObpReferenceObjectByHandleWithTag+0x547 (fffff806`119f6217)
nt!ObpReferenceObjectByHandleWithTag+0x163:
fffff806`119f5e33 488bd8          mov     rbx,rax
nt!ObpReferenceObjectByHandleWithTag+0x166:
fffff806`119f5e36 48c1fb10        sar     rbx,10h
nt!ObpReferenceObjectByHandleWithTag+0x16a:
fffff806`119f5e3a 4883e3f0        and     rbx,0FFFFFFFFFFFFFFF0h
nt!ObpReferenceObjectByHandleWithTag+0x16e:
fffff806`119f5e3e 833dcb51700000  cmp     dword ptr [nt!ObpTraceFlags (fffff806`120fb010)],0
nt!ObpReferenceObjectByHandleWithTag+0x175:
fffff806`119f5e45 0f852eb91e00    jne     nt!ObpReferenceObjectByHandleWithTag+0x1ebaa9 (fffff806`11be1779)
nt!ObpReferenceObjectByHandleWithTag+0x17b:
fffff806`119f5e4b 488b9424a0000000 mov     rdx,qword ptr [rsp+0A0h]
nt!ObpReferenceObjectByHandleWithTag+0x183:
fffff806`119f5e53 4c8d0da6a1a0ff  lea     r9,[nt!VrpRegistryString <PERF> (nt+0x0) (fffff806`11400000)]
nt!ObpReferenceObjectByHandleWithTag+0x18a:
fffff806`119f5e5a 488bc3          mov     rax,rbx
nt!ObpReferenceObjectByHandleWithTag+0x18d:
fffff806`119f5e5d 48c1e808        shr     rax,8
nt!ObpReferenceObjectByHandleWithTag+0x191:
fffff806`119f5e61 324318          xor     al,byte ptr [rbx+18h]
nt!ObpReferenceObjectByHandleWithTag+0x194:
fffff806`119f5e64 3205c2687000    xor     al,byte ptr [nt!ObHeaderCookie (fffff806`120fc72c)]
nt!ObpReferenceObjectByHandleWithTag+0x19a:
fffff806`119f5e6a 4885d2          test    rdx,rdx
nt!ObpReferenceObjectByHandleWithTag+0x19d:
fffff806`119f5e6d 0f8423010000    je      nt!ObpReferenceObjectByHandleWithTag+0x2c6 (fffff806`119f5f96)
nt!ObpReferenceObjectByHandleWithTag+0x1a3:
fffff806`119f5e73 384228          cmp     byte ptr [rdx+28h],al
nt!ObpReferenceObjectByHandleWithTag+0x1a6:
fffff806`119f5e76 0f851a010000    jne     nt!ObpReferenceObjectByHandleWithTag+0x2c6 (fffff806`119f5f96)
nt!ObpReferenceObjectByHandleWithTag+0x1ac:
fffff806`119f5e7c 8b8c2498000000  mov     ecx,dword ptr [rsp+98h]
nt!ObpReferenceObjectByHandleWithTag+0x1b3:
fffff806`119f5e83 81e5ffffff01    and     ebp,1FFFFFFh
nt!ObpReferenceObjectByHandleWithTag+0x1b9:
fffff806`119f5e89 80bc24a800000000 cmp     byte ptr [rsp+0A8h],0
nt!ObpReferenceObjectByHandleWithTag+0x1c1:
fffff806`119f5e91 7414            je      nt!ObpReferenceObjectByHandleWithTag+0x1d7 (fffff806`119f5ea7)
nt!ObpReferenceObjectByHandleWithTag+0x1c3:
fffff806`119f5e93 8bc5            mov     eax,ebp
nt!ObpReferenceObjectByHandleWithTag+0x1c5:
fffff806`119f5e95 f7d0            not     eax
nt!ObpReferenceObjectByHandleWithTag+0x1c7:
fffff806`119f5e97 85c1            test    ecx,eax
nt!ObpReferenceObjectByHandleWithTag+0x1c9:
fffff806`119f5e99 0f85ee020000    jne     nt!ObpReferenceObjectByHandleWithTag+0x4bd (fffff806`119f618d)
nt!ObpReferenceObjectByHandleWithTag+0x4bd:
fffff806`119f618d bf220000c0      mov     edi,0C0000022h
```
<br>

So the code arrive to *nt!ObpReferenceObjectByHandleWithTag+0x4bd* because ` ecx != eax `, ` eax = not(ebp & 0x1FFFFFF) `  and ` rbp = [rax+8] where rax = nt!ExpLookupHandleTableEntry() `. 
*ecx is read from the stack at [rsp+98h]*.
<br>

*ExpLookupHandleTableEntry()* returns the table entry from the handle number, in our case it would be 0xc4, and the handle table of the process that is calling *VirtualAlloc()*.
<br>

At this, point let's put a breakpoint on *ExpLookupHandleTableEntry() return*.
<br>
<p align="center">
  <img src="/assets/images/post_2022_07_30/img8.PNG">
</p>
<br>

*RAX = 0xffff89020dd77310* and *\*RAX+8 = 0x1ff7d6*.
Analyzing the handle entry table and the handle, i.e. index 0xc4, something strange appear.

```
kd> dt nt!_HANDLE_TABLE_ENTRY 0xffff89020dd77310
   +0x000 VolatileLowValue : 0n-4466944656595156999
   +0x000 LowValue         : 0n-4466944656595156999
   +0x000 InfoTable        : 0xc2023980`7050fff9 _HANDLE_TABLE_ENTRY_INFO
   +0x008 HighValue        : 0n2095062
   +0x008 NextFreeHandleEntry : 0x00000000`001ff7d6 _HANDLE_TABLE_ENTRY
   +0x008 LeafHandleValue  : _EXHANDLE
   +0x000 RefCountField    : 0n-4466944656595156999
   +0x000 Unlocked         : 0y1
   +0x000 RefCnt           : 0y0111111111111100 (0x7ffc)
   +0x000 Attributes       : 0y000
   +0x000 ObjectPointerBits : 0y11000010000000100011100110000000011100000101 (0xc2023980705)
   +0x008 GrantedAccessBits : 0y0000111111111011111010110 (0x1ff7d6)
   +0x008 NoRightsUpgrade  : 0y0
   +0x008 Spare1           : 0y000000 (0)
   +0x00c Spare2           : 0
kd> !handle 0xc4

PROCESS ffffc2023726c080
    SessionId: 1  Cid: 142c    Peb: 00839000  ParentCid: 113c
    DirBase: 1b1d57000  ObjectTable: ffff89020ea4cdc0  HandleCount:  55.
    Image: ShellCodeInjector.exe

Handle table at ffff89020ea4cdc0 with 55 entries in use

00c4: Object: ffffc20239807080  GrantedAccess: 001ff7d6 (Protected) (Audit) Entry: ffff89020dd77310
Object: ffffc20239807080  Type: (ffffc202314ac380) Process
    ObjectHeader: ffffc20239807050 (new version)
        HandleCount: 11  PointerCount: 354527
```
<br>

`HighValue == 2095062 == 0x1ff7d6 at ffff89020dd77310+8` that is the granted access mask to the object, i.e. the target process.
The access mask is incoherent with the one used in the test case, i.e. *PROCESS_ALL_ACCESS == 0x01fffff*.
This could lead to access denied on virtual alloc call. 
The access mask means, that *PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME* are not granted so it's impossible to allocate memory in the process!
<br>

We have at least two ways to bypass this:

1. Trying to bypass this resetting granted access in the object handle.
2. Understand where the access mask is modified and disable that feature.

The fastest way doing this is to intercept where the mask is changed in order to disable this once and not every time I have to attach to the process.

So, I put a breakpoint on the open process kernel implementation, i.e. *nt!PsOpenProcess*.
`bp nt!PsOpenProcess ".if ( poi(@r9) != 0xfd8) {gc}" `
<br>
<p align="center">
  <img  src="/assets/images/post_2022_07_30/img9.PNG">
</p>
<br>

Let's track the code flow until the end.

```
nt!ObpPreInterceptHandleCreate+0xa5:
fffff806`11a87ea5 e886fdffff      call    nt!ObpCallPreOperationCallbacks (fffff806`11a87c30)
```

So likely, a callback has been registered for process handle operations via *ObRegisterCallbacks()*.
<br>

```
nt!ObpCallPreOperationCallbacks+0x103:
fffff806`11a87d33 488b4908        mov     rcx,qword ptr [rcx+8]
nt!ObpCallPreOperationCallbacks+0x107:
fffff806`11a87d37 e81480d7ff      call    nt!guard_dispatch_icall (fffff806`117ffd50)
nt!guard_dispatch_icall:
fffff806`117ffd50 4c8b1d111ba000  mov     r11,qword ptr [nt!guard_icall_bitmap (fffff806`12201868)]
nt!guard_dispatch_icall+0x7:
fffff806`117ffd57 4885c0          test    rax,rax
nt!guard_dispatch_icall+0xa:
fffff806`117ffd5a 0f8d7a000000    jge     nt!guard_dispatch_icall+0x8a (fffff806`117ffdda)
nt!guard_dispatch_icall+0x10:
fffff806`117ffd60 4d85db          test    r11,r11
nt!guard_dispatch_icall+0x13:
fffff806`117ffd63 741c            je      nt!guard_dispatch_icall+0x31 (fffff806`117ffd81)
nt!guard_dispatch_icall+0x31:
fffff806`117ffd81 4c8b1dc0ce8f00  mov     r11,qword ptr [nt!retpoline_image_bitmap (fffff806`120fcc48)]
nt!guard_dispatch_icall+0x38:
fffff806`117ffd88 4c8bd0          mov     r10,rax
nt!guard_dispatch_icall+0x3b:
fffff806`117ffd8b 4d85db          test    r11,r11
nt!guard_dispatch_icall+0x3e:
fffff806`117ffd8e 742e            je      nt!guard_dispatch_icall+0x6e (fffff806`117ffdbe)
nt!guard_dispatch_icall+0x6e:
fffff806`117ffdbe 0faee8          lfence
nt!guard_dispatch_icall+0x71:
fffff806`117ffdc1 ffe0            jmp     rax
```
<br>

The function called that implements the antidebug is quite simple and basically get the process opened pid against a list of pids to check.
Indeed the anti debug module obtains the opened process pid via *PsGetProcessID()* 

```
nt!PsGetProcessId:
fffff806`1166ab30                 mov     rax,qword ptr [rcx+440h]
nt!PsGetProcessId+0x7:
fffff806`1166ab37                 ret
```

Check it against a list of pids contained by the anti debug module self.

```
test    rax,rax
je      fffff806`17481093
cmp     rax,0FFFFFFFFFFFFFFFFh
je      fffff806`17481093
lea     rbx,[fffff806`174969da0]
cmp     rax,qword ptr [rbx]
```

If the process pid opened is in the list then the access mask is checked to have the PROCESS_SUSPEND_RESUME bit enabled if so it is zeroed.

```
Disable PROCESS_SUSPEND_RESUME permission 
bt      dword ptr [rdx+4], 0Bh
jae     FFFFF80617481081
btr     dword ptr [rdx], 0Bh
```

More over the access mask is computed doing multiple and operation that disable other things like:

```
Disable PROCESS_TERMINATE 
and     dword ptr [rdx], 0FFFFFFFEh
...
Disable PROCESS_VM_OPERATION 
dword ptr [rdx], 0FFFFFFF7h
...
Disable PROCESS_VM_WRITE 
dword ptr [rdx], 0FFFFFFDFh
```

At this point, I just changed the list of the pids in order to not enter in the code block that alters the access mask, *ed fffff806`174969da0 0*.
Finally, I bypassed the anti debug trick.
<p align="center">
  <img src="/assets/images/post_2022_07_30/img10.PNG">
</p>

Finally, a consideration is required: I did a mess just to found that the handle's rights were different by the one I asked for. 
