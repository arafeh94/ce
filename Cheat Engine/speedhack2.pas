unit speedhack2;

{$MODE Delphi}

interface

uses Classes,LCLIntf, SysUtils, NewKernelHandler,CEFuncProc, symbolhandler, symbolhandlerstructs,
     autoassembler, dialogs,Clipbrd, commonTypeDefs, controls{$ifdef darwin},macport, FileUtil{$endif};

type TSpeedhack=class
  private
    fProcessId: dword;
    initaddress: ptrUint;
    lastSpeed: single;
    fHooked: TStringList;
    fFailed: TStringList;
    procedure hookOK(name: string);
    procedure hookFailed(name: string; reason: string);
    function getHookReport: string;
    function getHasFailures: boolean;
  public
    procedure setSpeed(speed: single);
    function getSpeed: single;
    property processid: dword read fProcessId;
    //which time functions got hooked and which failed (with the reason)
    property HookReport: string read getHookReport;
    property HasFailures: boolean read getHasFailures;
    constructor create;
    destructor destroy; override;
  end;

var speedhack: TSpeedhack;

implementation

uses frmAutoInjectUnit, networkInterface, networkInterfaceApi, ProcessHandlerUnit, Globals;

resourcestring
  rsFailureEnablingSpeedhackDLLInjectionFailed = 'Failure enabling speedhack. (DLL injection failed)';
  rsFailureConfiguringSpeedhackPart = 'Failure configuring speedhack part';
  rsFailureSettingSpeed = 'Failure setting speed';
  rsSpeedhackHooked = 'Hooked: %s';
  rsSpeedhackNotHooked = 'Not hooked (speedhack has no effect on code using these):';

procedure TSpeedhack.hookOK(name: string);
begin
  fHooked.Add(name);
  OutputDebugString('Speedhack: hooked '+name);
end;

procedure TSpeedhack.hookFailed(name: string; reason: string);
begin
  if reason='' then reason:='unknown error';
  fFailed.Add(name+' - '+reason);
  OutputDebugString('Speedhack: FAILED hooking '+name+': '+reason);
end;

function TSpeedhack.getHasFailures: boolean;
begin
  result:=(self<>nil) and (fFailed<>nil) and (fFailed.Count>0);
end;

function TSpeedhack.getHookReport: string;
var i: integer;
begin
  result:='';
  if (self=nil) or (fHooked=nil) then exit;

  result:=format(rsSpeedhackHooked, [fHooked.CommaText]);
  if fFailed.count>0 then
  begin
    result:=result+sLineBreak+sLineBreak+rsSpeedhackNotHooked;
    for i:=0 to fFailed.count-1 do
      result:=result+sLineBreak+'  '+fFailed[i];
  end;
end;

//runs a hook script. Unlike a bare autoassemble call this also notices a false
//result (not only exceptions), and records the outcome in the hook report
function runHookScript(sh: TSpeedhack; script: TStrings; name: string): boolean;
var errmsg: string;
begin
  errmsg:='';
  try
    result:=autoassemble(script,false);
    if not result then
      errmsg:='the auto assembler script failed';
  except
    on e: exception do
    begin
      result:=false;
      errmsg:=e.message;
    end;
  end;

  if result then
    sh.hookOK(name)
  else
    sh.hookFailed(name, errmsg);
end;

constructor TSpeedhack.create;
var i: integer;
    script: tstringlist;

    disableinfo: TDisableInfo;
    x: ptrUint;
//      y: dword;
    a,b: ptrUint;
    c: TCEConnection;
    e: boolean;

    fname: string;
    err: boolean;

    path: string;

    QPCAddress: ptruint;
    mi: TModuleInfo;
    mat: qword;
    machmodulebase: qword;
    machmodulesize: qword;

    HookMachAbsoluteTime: boolean;

    nokernelbase: boolean=false;
    NoGetTickCount: boolean=false;
    NoQPC: boolean=false;
    NoGetTickCount64: boolean=false;
    GetTickCountHooked: boolean=false;
    GetTickCount64Hooked: boolean=false;

  procedure hookSystemTimeFunction(apiname: string; newfunction: string; realvar: string);
  //optional hooks: a failure gets reported but doesn't stop the speedhack
  var fn: string;
      addr, kbaddr: ptruint;
      notfound: boolean;
  begin
    if symhandler.getAddressFromName(newfunction, true, notfound)=0 then
    begin
      //an older speedhack dll (from a previous Cheat Engine session) is still loaded in the target
      hookFailed(apiname, 'the speedhack dll loaded in the target is an older version without this hook. Restart the game');
      exit;
    end;

    //kernel32 forwards these to kernelbase, so hooking kernelbase covers both
    fn:='kernelbase.'+apiname;
    kbaddr:=symhandler.getAddressFromName(fn, true, notfound);
    if notfound then
    begin
      fn:='kernel32.'+apiname;
      addr:=symhandler.getAddressFromName(fn, true, notfound);
      if notfound then
      begin
        hookFailed(apiname, 'not found in kernelbase or kernel32 (older Windows version?)');
        exit;
      end;
    end;

    script.clear;
    a:=symhandler.getAddressFromName(realvar);
    b:=0;
    readprocessmemory(processhandle,pointer(a),@b,processhandler.pointersize,x);
    if b<>0 then //already configured
      generateAPIHookScript(script, fn, newfunction)
    else
      generateAPIHookScript(script, fn, newfunction, realvar);

    runHookScript(self, script, fn);
  end;

begin
  initaddress:=0;
  fHooked:=TStringList.create;
  fFailed:=TStringList.create;

  if processhandler.isNetwork then
  begin
    c:=getconnection;
    c.loadExtension(processhandle); //just to be sure

    symhandler.reinitialize;
    symhandler.waitforsymbolsloaded(true);
  end
  else
  begin
    try
      {$ifdef darwin}
      if not FileExists('/usr/local/lib/libspeedhack.dylib') then
      begin
        ForceDirectories('/usr/local/lib/');

        path:=cheatenginedir+'libspeedhack.dylib';
        if CopyFile(path, '/usr/local/lib/libspeedhack.dylib', true)=false then
        begin
          raise exception.create('Failure copying libspeedhack.dylib to /usr/local/lib');
        end;
      end;

      if symhandler.getmodulebyname('libspeedhack.dylib', mi)=false then
      begin
        injectdll('/usr/local/lib/libspeedhack.dylib','');
        symhandler.reinitialize;
      end;

      {$endif}

      {$ifdef windows}
      if processhandler.is64bit then
        fname:='speedhack-x86_64.dll'
      else
        fname:='speedhack-i386.dll';

      symhandler.waitforsymbolsloaded(true, 'kernel32.dll'); //speed it up (else it'll wait inside the symbol lookup of injectdll)

      OutputDebugString('Speedhack: calling waitForExports');
      symhandler.waitForExports;
      OutputDebugString('Speedhack: waitForExports returned');
      symhandler.getAddressFromName('speedhackversion_GetTickCount',false,e);
      if e then
      begin
        OutputDebugString('Speedhack: speedhackversion_GetTickCount not found. Injecting DLL');
        injectdll(CheatEngineDir+fname);

        OutputDebugString('Speedhack: after dll injection. Waiting for symbols reinitialized');
        symhandler.reinitialize;
        symhandler.waitforsymbolsloaded(true);
        OutputDebugString('Speedhack: after waitforsymbolsloaded. Calling symhandler.waitForExports');
        symhandler.waitForExports;
      end;
      {$endif}



    except
      on e: exception do
      begin
        raise exception.Create(rsFailureEnablingSpeedhackDLLInjectionFailed+': '+e.message);
      end;
    end;
  end;


  script:=tstringlist.Create;
  try
    if processhandler.isNetwork then
    begin
      OutputDebugString('Speedhack: networked');
      //linux


      //gettimeofday

      if symhandler.getAddressFromName('vdso.gettimeofday', true, err)>0 then //prefered
        fname:='vdso.gettimeofday'
      else
      if symhandler.getAddressFromName('libc.gettimeofday', true, err)>0 then //secondary
        fname:='libc.gettimeofday'
      else
      if symhandler.getAddressFromName('gettimeofday', true, err)>0 then //really nothing else ?
        fname:='gettimeofday'
      else
        fname:=''; //give up


      if fname<>'' then //hook gettimeofday
      begin
        //check if it already has a a speedhack running
        a:=symhandler.getAddressFromName('real_gettimeofday');
        b:=0;

        readprocessmemory(processhandle,pointer(a),@b,processhandler.pointersize,x);
        if b=0 then //not yet hooked
        begin
          generateAPIHookScript(script, fname, 'new_gettimeofday', 'real_gettimeofday');

          try
            //Clipboard.AsText:=script.text;
            autoassemble(script,false);
          except
          end;
        end;
      end;

      script.clear;
      //clock_gettime
      if symhandler.getAddressFromName('vdso.clock_gettime', true,err)>0 then //prefered
        fname:='vdso.clock_gettime'
      else
      if symhandler.getAddressFromName('libc.clock_gettime', true, err)>0 then //seen this on android
        fname:='libc.clock_gettime'
      else
      if symhandler.getAddressFromName('librt.clock_gettime', true, err)>0 then //secondary
        fname:='librt.clock_gettime'
      else
      if symhandler.getAddressFromName('clock_gettime', true, err)>0 then //really nothing else ?
        fname:='clock_gettime'
      else
        fname:=''; //give up


      if fname<>'' then //hook clock_gettime
      begin
        //check if it already has a a speedhack running
        a:=symhandler.getAddressFromName('real_clock_gettime');
        b:=0;

        readprocessmemory(processhandle,pointer(a),@b,processhandler.pointersize,x);
        if b=0 then //not yet hooked
        begin
          generateAPIHookScript(script, fname, 'new_clock_gettime', 'real_clock_gettime');

          try
           // Clipboard.AsText:=script.text;
            autoassemble(script,false);
          except
          end;
        end;
      end;

    end
    else
    begin
      //local
      OutputDebugString('Speedhack: local');

      {$ifdef darwin}
      OutputDebugString('Speedhack: mac');
      HookMachAbsoluteTime:=false;
      if speedhack_HookMachAbsoluteTime then
      begin

        mat:=symhandler.getAddressFromName('mach_absolute_time', false, err);
        if symhandler.getmodulebyaddress(mat,mi) then
        begin
          machmodulebase:=mi.baseaddress;
          machmodulesize:=mi.basesize;


          if processhandler.is64Bit then
          begin
            script.add('machmodulebase:');
            script.add('dq '+inttohex(machmodulebase,8));

            script.Add('machmodulesize:');
            script.Add('dq '+inttohex(machmodulesize,8));
          end
          else
          begin
            script.add('machmodulebase:');
            script.add('dd '+inttohex(machmodulebase,8));

            script.add('machmodulesize:');
            script.add('dd '+inttohex(machmodulesize,8));
          end;

          HookMachAbsoluteTime:=true;
        end;
        //  raise exception.create('mach_absolute_time not found');

      end;


      a:=symhandler.getAddressFromName('realGetTimeOfDay') ;
      b:=0;
      readprocessmemory(processhandle,pointer(a),@b,processhandler.pointersize,x);
      if b<>0 then //already configured
      begin
        generateAPIHookScript(script, 'gettimeofday', 'speedhackversion_GetTimeOfDay','','1');
        if HookMachAbsoluteTime then
          generateAPiHookScript(script, 'mach_absolute_time', 'speedhackversion_MachAbsoluteTime','','2');
      end
      else
      begin
        generateAPIHookScript(script, 'gettimeofday', 'speedhackversion_GetTimeOfDay', 'realGetTimeOfDay','1');
        if HookMachAbsoluteTime then
          generateAPiHookScript(script, 'mach_absolute_time', 'speedhackversion_MachAbsoluteTime','realMachAbsoluteTime','2');
      end;

      {$endif}

      {$ifdef windows}
      OutputDebugString('Speedhack: windows');
      noKernelBase:=false; //assume it present


      //check if it already has a a speedhack script running

      fname:='kernelbase.GetTickCount';
      a:=symhandler.getAddressFromName(fname, true,e);
      if e then
      begin
        noKernelBase:=true;
        OutputDebugString('No kernelbase.GetTickCount');

        fname:='kernel32.GetTickCount';
        a:=symhandler.getAddressFromName(fname, true,e);

        if e then
        begin
          outputdebugstring('No kernel32.GetTickCount');
          fname:='GetTickCount';
          a:=symhandler.getAddressFromName(fname, true,e);

          if e then
          begin
            NoGetTickCount:=true;
            outputdebugstring('No GetTickCount');
          end;
        end;
      end;

      if processhandler.is64bit then
        script.Add('alloc(init,512,'+fname+')')
      else
        script.Add('alloc(init,512)');

      if NoGetTickCount=false then
      begin
        OutputDebugString('Speedhack: hooking '+fname);
        a:=symhandler.getAddressFromName('realgettickcount', true) ;
        b:=0;
        readprocessmemory(processhandle,pointer(a),@b,processhandler.pointersize,x);
        if b<>0 then //already configured
          generateAPIHookScript(script, fname, 'speedhackversion_GetTickCount')
        else
          generateAPIHookScript(script, fname, 'speedhackversion_GetTickCount', 'realgettickcount');
      end;
      {$endif}

      try
        disableinfo:=TDisableInfo.create;
        try
          OutputDebugString('Speedhack: init1');
          //part 1 also allocates the "init" region setSpeed needs, so nothing works without it
          if autoassemble(script,false,true,false,false,disableinfo)=false then
            raise exception.create('the auto assembler script failed');
          //clipboard.AsText:=script.text;

          //fill in the address for the init region
          for i:=0 to length(disableinfo.allocs)-1 do
            if disableinfo.allocs[i].varname='init' then
            begin
              initaddress:=disableinfo.allocs[i].address;
              break;
            end;
        finally
          disableinfo.free;
        end;


      except
        on e:exception do
        begin
          clipboard.AsText:=script.text;
          {$ifdef windows}
          if NoGetTickCount=false then hookFailed(fname, e.message);
          {$endif}
          raise exception.Create(rsFailureConfiguringSpeedhackPart+' 1: '+e.message);
        end;
      end;
      {$ifdef windows}

      if NoGetTickCount then
        hookFailed('GetTickCount', 'not found')
      else
      begin
        hookOK(fname);
        GetTickCountHooked:=true;
      end;

      //the extra entry points below jump straight into speedhackversion_GetTickCount(64).
      //That function calls the trampoline the main hook created, so only add
      //them when that hook is in place (else they'd call a nil pointer)

      if GetTickCountHooked and (nokernelbase=false) then //hook kernel32.GetTickCount as well
      begin
        //when kernel32.GetTickCount is the same code as the kernelbase one it's already
        //hooked, and writing a (bigger) jmp over that hook would corrupt the function
        if symhandler.getAddressFromName('kernel32.GetTickCount',true,err)<>symhandler.getAddressFromName(fname,true,e) then
        begin
          script.Clear;
          script.Add('kernel32.GetTickCount:');
          script.Add('jmp speedhackversion_GetTickCount');
          runHookScript(self, script, 'kernel32.GetTickCount');
        end;
      end;

      //timegettime
      if symhandler.getAddressFromName('timeGetTime',true,err)>0 then //might not be loaded
      begin
        if GetTickCountHooked then
        begin
          script.Clear;
          script.Add('timeGetTime:');
          script.Add('jmp speedhackversion_GetTickCount');
          runHookScript(self, script, 'timeGetTime');
        end
        else
          hookFailed('timeGetTime', 'needs the GetTickCount hook');
      end;


      //qpc
      fname:='ntdll.RtlQueryPerformanceCounter';
      qpcaddress:=symhandler.getAddressFromName(fname,true, err);
      if err then
      begin
        fname:='kernel32.QueryPerformanceCounter';
        qpcaddress:=symhandler.getAddressFromName(fname,true, err);

        if err then
        begin
          fname:='';
          NoQPC:=true;
          hookFailed('QueryPerformanceCounter', 'not found');
        end;
      end;


      if not noqpc then
      begin
        OutputDebugString('Speedhack: hooking '+fname);
        script.clear;
        a:=symhandler.getAddressFromName('realQueryPerformanceCounter') ;
        b:=0;
        readprocessmemory(processhandle,pointer(a),@b,processhandler.pointersize,x);

        if b<>0 then //already configured
          generateAPIHookScript(script, inttohex(qpcaddress,8), 'speedhackversion_QueryPerformanceCounter')
        else
          generateAPIHookScript(script, inttohex(qpcaddress,8), 'speedhackversion_QueryPerformanceCounter', 'realQueryPerformanceCounter');

        //required: InitializeSpeedhack calls the QPC trampoline unconditionally
        if not runHookScript(self, script, fname) then
          raise exception.Create(rsFailureConfiguringSpeedhackPart+' 2: '+fFailed[fFailed.count-1]);
      end;

      //gettickcount64
      fname:='kernelbase.GetTickCount64';
      a:=symhandler.getAddressFromName(fname,true,err);
      if err then
      begin
        nokernelbase:=true;
        fname:='kernel32.GetTickCount64';
        a:=symhandler.getAddressFromName(fname,true,err);
        if err then
        begin
          fname:='GetTickCount64';
          a:=symhandler.getAddressFromName(fname,true,err);
          if err then
          begin
            NoGetTickCount64:=true;
            hookFailed('GetTickCount64', 'not found');
          end;
        end;
      end;

      if not NoGetTickCount64 then
      begin
        script.clear;
        a:=symhandler.getAddressFromName('realGetTickCount64') ;
        b:=0;
        readprocessmemory(processhandle,pointer(a),@b,processhandler.pointersize,x);
        if b<>0 then //already configured
          generateAPIHookScript(script, fname, 'speedhackversion_GetTickCount64')
        else
          generateAPIHookScript(script, fname, 'speedhackversion_GetTickCount64', 'realGetTickCount64');

        if not runHookScript(self, script, fname) then
          raise exception.Create(rsFailureConfiguringSpeedhackPart+' 3: '+fFailed[fFailed.count-1]);

        GetTickCount64Hooked:=true;

        if GetTickCount64Hooked and (not nokernelbase) then
        begin
          if (symhandler.getAddressFromName('kernel32.GetTickCount64',true,err)>0) and
             (symhandler.getAddressFromName('kernel32.GetTickCount64',true,err)<>symhandler.getAddressFromName(fname,true,e)) then
          begin
            script.Clear;
            script.Add('kernel32.GetTickCount64:');
            script.Add('jmp speedhackversion_GetTickCount64');
            runHookScript(self, script, 'kernel32.GetTickCount64');
          end;
        end;

      end;

      //system time (FILETIME). Used by e.g. std::chrono::system_clock and many
      //engines' frame timers. Optional
      hookSystemTimeFunction('GetSystemTimeAsFileTime', 'speedhackversion_GetSystemTimeAsFileTime', 'realGetSystemTimeAsFileTime');
      hookSystemTimeFunction('GetSystemTimePreciseAsFileTime', 'speedhackversion_GetSystemTimePreciseAsFileTime', 'realGetSystemTimePreciseAsFileTime');

      OutputDebugString(pchar('Speedhack: '+HookReport));
      {$endif}


    end;

  finally
    script.free;
  end;

  setspeed(1);
  fprocessid:=processhandlerunit.processid;

end;

destructor TSpeedhack.destroy;
var script: tstringlist;
    i: integer;
    x: dword;
begin
  if fprocessid=processhandlerunit.ProcessID then
  begin

    try
      setSpeed(1);
    except
    end;
  end;

  //do not undo the speedhack script (not all games handle a counter that goes back)

  if fHooked<>nil then fHooked.free;
  if fFailed<>nil then fFailed.free;

  inherited destroy;
end;

function TSpeedhack.getSpeed: single;
begin
  if self=nil then
    result:=1
  else
    result:=lastspeed;
end;

procedure TSpeedhack.setSpeed(speed: single);
var x: single;
    script: Tstringlist;

begin
  if processhandler.isNetwork then
  begin
    getConnection.speedhack_setSpeed(processhandle, speed);
    lastspeed:=speed;
  end
  else
  begin
    x:=speed;
    script:=tstringlist.Create;
    try
      script.add('CreateThread('+inttohex(initaddress,8)+')');
      script.add('label(newspeed)');
      script.add(inttohex(initaddress,8)+':');
      if processhandler.is64Bit then
      begin
        script.add('sub rsp,#40');
        script.add('movss xmm0,[newspeed]');
      end
      else
        script.add('push [newspeed]');

      script.add('call InitializeSpeedhack');

      if processhandler.is64Bit then
      begin
        script.add('add rsp,#40');
        script.add('ret');
      end
      else
      begin
        script.add('ret 4');
      end;

      script.add('newspeed:');
      script.add('dd '+inttohex(pdword(@x)^,8));

      try

  //      showmessage(script.Text);
       // Clipboard.AsText:=script.text;
        autoassemble(script,false);
      except
        raise exception.Create(rsFailureSettingSpeed);
      end;

      lastspeed:=speed;
    finally
      script.free;
    end;

  end;

end;

{
alloc(bla,2048)
alloc(newspeed,4);

bla:
sub rsp,28

movss xmm0,[newspeed]
call speedhack_initializeSpeed

add rsp,28
ret

newspeed:
dd (float)-1.0

createthread(bla)
}

end.
