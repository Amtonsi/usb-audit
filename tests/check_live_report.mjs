// Проверка настоящей вкладки file:// и пользовательского обновителя, без изменений установки.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {existsSync} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {setTimeout as delay} from 'node:timers/promises';

const temp=await fs.mkdtemp(path.join(os.tmpdir(),'usb-report-test-'));
const script=fileURLToPath(new URL('../src/Report.ps1',import.meta.url));
const env={...process.env,PROGRAMDATA:path.join(temp,'Data'),LOCALAPPDATA:path.join(temp,'Local')};
const data=path.join(env.PROGRAMDATA,'LocalUsbAudit','Data');
const file=path.join(data,'Active','events.jsonl');
const directory=path.join(env.LOCALAPPDATA,'LocalUsbAudit','Reports');
const report=path.join(directory,'USB-Audit.html');
const signal=path.join(directory,'USB-Audit-status.css');
const profile=path.join(temp,'browser');
const downloads=path.join(temp,'downloads');
const browser=[path.join(process.env.PROGRAMFILES,'Google/Chrome/Application/chrome.exe'),
    path.join(process.env['PROGRAMFILES(X86)'],'Microsoft/Edge/Application/msedge.exe')].find(existsSync);
assert.ok(browser,'Установите Chrome или Edge для проверки');
const names=[];
async function until(label,fn){
    const stop=Date.now()+25000;
    let last;
    while(Date.now()<stop){
        try{last=await fn();if(last)return last;}catch(e){last=e.message;}
        await delay(250);
    }
    throw Error(label+'; наблюдалось: '+JSON.stringify(last));
}
async function stop(child){
    if(!child || child.exitCode!==null || child.signalCode!==null)return;
    const ended=once(child,'exit');child.kill();await ended;
}
let worker,chrome,ws;
try {
    await Promise.all([path.join(data,'Active'),path.join(data,'Archive'),downloads].map(d=>fs.mkdir(d,{recursive:true})));
    const event={type:'connect',deviceId:'TEST',session:'test',time:new Date().toISOString()};
    await fs.writeFile(file,JSON.stringify(event)+'\n','utf8');
    worker=spawn('powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',script,'-Watch'],
        {env,stdio:'ignore',windowsHide:true});
    await until('Свежий HTML и метка',()=>existsSync(signal)&&existsSync(report));
    const before=(await fs.stat(report)).mtimeMs;
    chrome=spawn(browser,['--headless=new','--remote-debugging-port=0','--no-first-run','--disable-extensions',
        '--disable-background-networking','--no-default-browser-check','--user-data-dir='+profile,pathToFileURL(report).href],
        {stdio:'ignore',windowsHide:true});
    const port=await until('Порт изолированного браузера',async()=>(await fs.readFile(path.join(profile,'DevToolsActivePort'),'utf8')).split('\n')[0]);
    const tab=await until('Вкладка отчёта',async()=>(await (await fetch('http://127.0.0.1:'+port+'/json/list')).json()).find(t=>t.type==='page'&&t.url.startsWith('file:')));
    ws=new WebSocket(tab.webSocketDebuggerUrl);await once(ws,'open');
    let number=0;
    const pending=new Map();
    ws.addEventListener('message',e=>{
        const m=JSON.parse(e.data);if(!pending.has(m.id))return;
        const done=pending.get(m.id);pending.delete(m.id);done(m);
    });
    async function command(method,params={}){
        const id=++number;
        const answer=new Promise(done=>pending.set(id,done));
        ws.send(JSON.stringify({id,method,params}));const message=await answer;
        if(message.error)throw Error(JSON.stringify(message.error));return message.result;
    }
    async function evaluate(expression){
        const r=await command('Runtime.evaluate',{expression,returnByValue:true});
        if(r.exceptionDetails)throw Error(r.exceptionDetails.text);return r.result.value;
    }
    const enabled="document.getElementById('live-state')?.textContent==='Автообновление включено'";
    try { await until('Включено автообновление',()=>evaluate(enabled)); }
    catch(error){
        console.error(await evaluate("({state:document.getElementById('live-state')?.textContent,hidden:document.hidden,href:location.href,liveUri:meta.liveUri,generation:meta.generation})"),await fs.readFile(signal,'utf8'));
        throw error;
    }
    await delay(5400);assert.equal(before,(await fs.stat(report)).mtimeMs,'Пустой цикл перезаписал HTML');
    await evaluate("document.getElementById('file-mode').value='all';filterReport(true)");
    await fs.appendFile(file,JSON.stringify({...event,type:'file',time:new Date().toISOString(),path:'F:\\live-test.txt',accessMask:'0x2'})+'\n');
    await until('Изменение отображено в той же вкладке',()=>evaluate("document.querySelector('#files tbody')?.textContent.includes('live-test.txt')&&document.getElementById('file-mode')?.value==='all'"));
    names.push('запись в открытой вкладке, сохранение режима, отсутствие холостых перезаписей');
    // При недоступном источнике видны причина и результаты последней удачной сборки.
    const held=file+'.hold';const liveStamp=(await fs.stat(report)).mtimeMs;
    await fs.rename(file,held);
    await until('Отказ чтения источника',()=>evaluate("document.getElementById('live-state')?.textContent.includes('недоступно')"));
    assert.equal((await fs.stat(report)).mtimeMs,liveStamp);
    await fs.rename(held,file);
    await until('Восстановление доступа',()=>evaluate(enabled));
    const archiveName='usb-20261124T000000Z-'+'a'.repeat(32)+'.jsonl';
    const archiveFile=path.join(data,'Archive',archiveName);
    await fs.writeFile(archiveFile,JSON.stringify({...event,deviceId:'SECOND',session:'archived',time:'2024-01-01T00:00:00Z'})+'\n');
    await until('Новый архив',()=>evaluate("document.getElementById('total-devices')?.textContent==='2'"));
    const archiveJob=spawn('powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',script,'-ArchiveName',archiveName,'-NoOpen'],{env,stdio:'ignore',windowsHide:true});
    assert.equal((await once(archiveJob,'exit'))[0],0);assert.ok(existsSync(path.join(directory,'Archive-'+path.basename(archiveName,'.jsonl')+'.html')));
    await fs.unlink(archiveFile);
    await until('Удалённый архив исключён',()=>evaluate("document.getElementById('total-devices')?.textContent==='1'"));
    names.push('сохранение последнего отчёта при ошибке, восстановление, создание и удаление архива');
    await command('Browser.setDownloadBehavior',{behavior:'allow',downloadPath:downloads});
    await evaluate("document.getElementById('export').click()");
    const saved=await until('Портативный HTML',async()=>(await fs.readdir(downloads)).find(f=>f.endsWith('.html')));
    const savedHtml=await fs.readFile(path.join(downloads,saved),'utf8');
    assert.ok(!savedHtml.match(/<meta[^>]+Content-Security-Policy[^>]+>/i)[0].includes('file:'));
    const meta=JSON.parse(Buffer.from(savedHtml.match(/id="report-meta">([^<]+)</)[1],'base64'));
    assert.equal(meta.liveUri,undefined);assert.equal(meta.generation,undefined);
    // Читатель может скопировать и сам файл через Проводник: тогда также должен открыться снимок.
    const copy=path.join(temp,'copy.html');await fs.copyFile(report,copy);
    await command('Page.navigate',{url:pathToFileURL(copy).href});
    await until('Копия независима',()=>evaluate("document.getElementById('live-state')?.textContent==='Сохранённый снимок'&&document.getElementById('total-files')?.textContent==='1'"));
    names.push('экспорт и файловая копия автономны');
    await stop(worker);await fs.unlink(signal);
    await command('Page.navigate',{url:pathToFileURL(report).href});
    await until('Отсутствие обновителя',()=>evaluate("document.getElementById('live-state')?.textContent.includes('недоступно')&&document.getElementById('total-files')?.textContent==='1'"));
    names.push('снимок доступен без обновителя');
    console.log('Проверено: '+names.join('; '));
    await command('Browser.close');
} finally {
    ws?.close();await stop(chrome);await stop(worker);
    await fs.rm(temp,{recursive:true,force:true,maxRetries:5,retryDelay:300});
}
