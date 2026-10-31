unit speedhackmain;

{$MODE Delphi}


interface
uses windows, classes, sysutils;

procedure InitializeSpeedhack(speed: single); stdcall;

procedure InitDLL;

type TGetTickCount=function: DWORD; stdcall;
type TGetTickCount64=function: QWORD; stdcall;
type TQueryPerformanceCounter=function(var x: int64): BOOL; stdcall;
type TGetSystemTimeAsFileTime=procedure(var ft: int64); stdcall; //FILETIME is 2 dwords = one int64

function speedhackversion_GetTickCount: DWORD; stdcall;
function speedhackversion_GetTickCount64: QWORD; stdcall;
function speedhackversion_QueryPerformanceCounter(var x: int64): BOOL; stdcall;
procedure speedhackversion_GetSystemTimeAsFileTime(var ft: int64); stdcall;
procedure speedhackversion_GetSystemTimePreciseAsFileTime(var ft: int64); stdcall;


var CETick: dword;
    CETick64: int64;

    PerformanceFrequency: int64;
    PerformanceFrequencyMS: int64;
    acceleration: single;
    sleeptime: dword;
    slow: boolean;
    tickerstopped: boolean;
    speedhackenabled: boolean;

    winmmlib,kernel32lib: thandle;

    //5.5:
    confighaschanged: integer;

    //double instead of single: a single only has a 24-bit mantissa, so
    //(elapsed ticks)*multiplier lost precision once more than ~2^24 ticks had
    //passed since the last speed change (1.6 seconds of 10MHz QPC ticks), making
    //the returned time advance in ever growing steps
    speedmultiplier: double;

    //pointers to trampolines that call the original (unhooked) functions.
    //Filled in by the hook scripts Cheat Engine writes (see speedhack2.pas)
    realgettime: pointer;
    realGetTickCount: pointer;
    realGetTickCount64: pointer;
    realQueryPerformanceCounter: pointer;
    realGetSystemTimeAsFileTime: pointer;
    realGetSystemTimePreciseAsFileTime: pointer;

    initialoffset: dword;
    initialtime: dword;
    initialoffset64: int64;
    initialtime64: int64;

    initialoffset_tc64: QWord;
    initialtime_tc64: QWord;

    initialoffset_ft: int64;
    initialtime_ft: int64;
    initialoffset_ftp: int64;
    initialtime_ftp: int64;

    //lets Cheat Engine tell which version of this dll is injected (old ones
    //don't export this, or the GetSystemTime* hooks)
    speedhackdllversion: dword=2;


implementation

var
  //one reentrant lock for all timer state. Replaces the old hand made
  //spinlock, which was only safe when compiled without optimizations
  SpeedLock: TRTLCriticalSection;

  //per-thread "already inside a speedhack function" flag. Some real
  //functions call other hooked ones internally (e.g. GetSystemTimePreciseAsFileTime
  //uses RtlQueryPerformanceCounter). Without this the inner result would be
  //scaled and then the outer one scaled again.
  GuardTLS: DWORD=TLS_OUT_OF_INDEXES;

function EnterGuard: boolean; inline;
var e: DWORD;
begin
  if GuardTLS=TLS_OUT_OF_INDEXES then exit(true);

  e:=GetLastError; //TlsGetValue/TlsSetValue change the last error, the caller of a time function doesn't expect that
  result:=TlsGetValue(GuardTLS)=nil;
  if result then
    TlsSetValue(GuardTLS, pointer(1));
  SetLastError(e);
end;

procedure LeaveGuard; inline;
var e: DWORD;
begin
  if GuardTLS=TLS_OUT_OF_INDEXES then exit;

  e:=GetLastError;
  TlsSetValue(GuardTLS, nil);
  SetLastError(e);
end;

function speedhackversion_GetTickCount: DWORD; stdcall;
var currentTime: dword;
begin
  //also used for timeGetTime
  if not EnterGuard then
    exit(TGetTickCount(realgettickcount)());

  EnterCriticalSection(SpeedLock);

  currentTime:=TGetTickCount(realgettickcount);
  //time past since activation, mulitplied by speed multiplier
  result:=dword(trunc(dword(currentTime-initialtime)*speedmultiplier)+initialoffset);

  LeaveCriticalSection(SpeedLock);
  LeaveGuard;
end;

function speedhackversion_GetTickCount64: QWORD; stdcall;
var currentTime: qword;
begin
  if not EnterGuard then
    exit(TGetTickCount64(realgettickcount64)());

  EnterCriticalSection(SpeedLock);

  currentTime:=TGetTickCount64(realgettickcount64);
  //time past since activation, mulitplied by speed multiplier
  result:=qword(trunc((currentTime-initialtime_tc64)*speedmultiplier))+initialoffset_tc64;

  LeaveCriticalSection(SpeedLock);
  LeaveGuard;
end;

function speedhackversion_QueryPerformanceCounter(var x: int64): BOOL; stdcall;
var currentTime64: int64;
    newx: int64;
begin
  if not EnterGuard then
    exit(TQueryPerformanceCounter(realQueryPerformanceCounter)(x));

  EnterCriticalSection(SpeedLock);

  currentTime64:=0;
  result:=TQueryPerformanceCounter(realQueryPerformanceCounter)(currentTime64);

  //time past since activation, multiplied by speed multiplier
  newx:=trunc((currentTime64-initialtime64)*speedmultiplier)+initialoffset64;

  LeaveCriticalSection(SpeedLock);
  LeaveGuard;

  x:=newx; //access violation possible here
end;

procedure speedhackversion_GetSystemTimeAsFileTime(var ft: int64); stdcall;
var currentTime, newft: int64;
begin
  if not EnterGuard then
  begin
    TGetSystemTimeAsFileTime(realGetSystemTimeAsFileTime)(ft);
    exit;
  end;

  EnterCriticalSection(SpeedLock);

  currentTime:=0;
  TGetSystemTimeAsFileTime(realGetSystemTimeAsFileTime)(currentTime);
  newft:=trunc((currentTime-initialtime_ft)*speedmultiplier)+initialoffset_ft;

  LeaveCriticalSection(SpeedLock);
  LeaveGuard;

  ft:=newft;
end;

procedure speedhackversion_GetSystemTimePreciseAsFileTime(var ft: int64); stdcall;
var currentTime, newft: int64;
begin
  if not EnterGuard then
  begin
    TGetSystemTimeAsFileTime(realGetSystemTimePreciseAsFileTime)(ft);
    exit;
  end;

  EnterCriticalSection(SpeedLock);

  currentTime:=0;
  TGetSystemTimeAsFileTime(realGetSystemTimePreciseAsFileTime)(currentTime);
  newft:=trunc((currentTime-initialtime_ftp)*speedmultiplier)+initialoffset_ftp;

  LeaveCriticalSection(SpeedLock);
  LeaveGuard;

  ft:=newft;
end;

procedure InitializeSpeedhack(speed: single); stdcall;
{
Called by createremotethread
}
var t: int64;
begin
  EnterCriticalSection(SpeedLock); //reentrant, so the calls to the hooked functions below can take it again

  initialoffset:=gettickcount; //get the time the process currently sees (could be fake)
  initialtime:=TGetTickCount(realgettickcount);   //get the real time

  QueryPerformanceCounter(initialoffset64);
  TQueryPerformanceCounter(realQueryPerformanceCounter)(initialtime64);

  if realGetTickCount64<>nil then   //xp doesn't have this
  begin
    initialoffset_tc64:=GetTickCount64;
    initialtime_tc64:=TGetTickCount64(realGetTickCount64);
  end;

  //the GetSystemTime* hooks are optional. Only touch their state when hooked.
  //The current fake time comes from our own function (still using the old speed)
  if realGetSystemTimeAsFileTime<>nil then
  begin
    speedhackversion_GetSystemTimeAsFileTime(t);
    initialoffset_ft:=t;
    TGetSystemTimeAsFileTime(realGetSystemTimeAsFileTime)(initialtime_ft);
  end;

  if realGetSystemTimePreciseAsFileTime<>nil then
  begin
    speedhackversion_GetSystemTimePreciseAsFileTime(t);
    initialoffset_ftp:=t;
    TGetSystemTimeAsFileTime(realGetSystemTimePreciseAsFileTime)(initialtime_ftp);
  end;

  speedmultiplier:=speed;

  LeaveCriticalSection(SpeedLock);
end;


procedure InitDLL;
begin
  InitializeCriticalSectionAndSpinCount(SpeedLock, 4000);
  GuardTLS:=TlsAlloc;

  speedmultiplier:=1;
  confighaschanged:=0; //not changed, speed is 1
  initialoffset:=gettickcount;
  initialtime:=initialoffset;
  QueryPerformanceCounter(initialoffset64);
  initialtime64:=initialoffset64;

  //with offset=time=0 and a multiplier of 1 the GetSystemTime* hooks return the
  //real time until InitializeSpeedhack is called
  initialoffset_ft:=0;
  initialtime_ft:=0;
  initialoffset_ftp:=0;
  initialtime_ftp:=0;

  loadlibrary('winmm.dll');
end;

end.
